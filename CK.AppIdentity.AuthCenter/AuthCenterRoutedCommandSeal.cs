using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The seal of the routed commands that carry a user's proof (see <see cref="RoutedCommandSeal"/>). A routed command
/// without a proof is not sealed.
/// <list type="bullet">
///   <item>
///   At the origin, the session party encrypts the user's proof (the token and the hash of the binding secret) and the
///   command for the destination (its encryption key comes from the <see cref="IPartyEncryptionKeyDirectory"/> of the
///   origin), with the header of the seal as associated data, then signs the header and the digest of the ciphertext
///   (encrypt, then sign). The envelope carries the seal, not the proof: the hops see neither the command nor the proof.
///   </item>
///   <item>
///   When the key of the destination can't be known, the command is signed only, in clear, with the proof in the
///   envelope (a warning).
///   </item>
///   <item>
///   At the destination, an encrypted command is decrypted with the encryption keys of the local party: the proof goes
///   back into the envelope, the command is read from the decrypted bytes. The Authentication Center verifies the seal
///   with the proof (see <see cref="AuthCenterProofVerifier"/>).
///   </item>
/// </list>
/// When the origin can't seal (no key management), the proof is not sent: the command travels without it.
/// </summary>
public sealed class AuthCenterRoutedCommandSeal : ICrisRoutedCommandSeal
{
    /// <inheritdoc />
    public async ValueTask<bool> SealAsync( IActivityMonitor monitor,
                                            IServiceProvider services,
                                            ILocalParty origin,
                                            string destination,
                                            IAbstractCommand command,
                                            IPartyRoutedCommand routed,
                                            ICrisCallEnvelope envelope )
    {
        if( envelope is not IAuthenticationCallEnvelope { Token: { } token } proof || routed.SealedCommand == null ) return true;
        var keys = origin.GetFeature<ILocalKeys>();
        if( keys == null )
        {
            monitor.Warn( $"'{origin}' cannot seal the command routed to '{destination}': the user's proof is not sent." );
            proof.Token = null;
            proof.BindingSecretHash = null;
            return true;
        }
        var utcNow = DateTime.UtcNow;
        var key = origin.GetFeature<IPartyEncryptionKeyDirectory>() is { } directory
                    ? await directory.GetPartyEncryptionKeyAsync( monitor, destination ).ConfigureAwait( false )
                    : null;
        if( key == null )
        {
            monitor.Warn( $"No verified encryption key for '{destination}': the command routed to it is signed only, in clear." );
            (proof.RoutedSeal, proof.RoutedSignature) = RoutedCommandSeal.Create( keys, destination, token, routed.SealedCommand, utcNow );
            return true;
        }
        var header = RoutedCommandSeal.CreateHeader( destination, token, utcNow, encrypted: true );
        var plain = Pack( token, proof.BindingSecretHash, routed.SealedCommand );
        try
        {
            routed.SealedCommand = PartyEncryption.Encrypt( key.Value.PublicKey, plain, header, utcNow, out _ );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( plain );
        }
        proof.RoutedSeal = header;
        proof.RoutedSignature = RoutedCommandSeal.Sign( keys, header, routed.SealedCommand, utcNow );
        // The proof travels encrypted: the hops never hold it.
        proof.Token = null;
        proof.BindingSecretHash = null;
        return true;
    }

    /// <inheritdoc />
    public ValueTask<byte[]?> UnsealAsync( IActivityMonitor monitor, IRemoteParty sender, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
    {
        if( envelope is not IAuthenticationCallEnvelope { RoutedSeal: { } header } proof
            || !RoutedCommandSeal.IsEncrypted( header )
            || routed.SealedCommand == null )
        {
            // Signed only, in clear (or not sealed): the seal is verified with the proof (see AuthCenterProofVerifier).
            return ValueTask.FromResult( routed.SealedCommand );
        }
        var keys = sender.Owner.GetFeature<ILocalKeys>();
        var utcNow = DateTime.UtcNow;
        if( keys == null
            || !PartyEncryption.TryDecrypt( monitor,
                                            routed.SealedCommand,
                                            id => keys.FindEncryptionKey( id, utcNow ),
                                            header,
                                            utcNow,
                                            RoutedCommandSeal.Lifetime + RoutedCommandSeal.ClockSkew,
                                            out var plain,
                                            out _ ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The command routed from '{routed.Via[0]}' by '{sender}' can't be decrypted here: it is refused." );
            return ValueTask.FromResult<byte[]?>( null );
        }
        if( !TryUnpack( plain!, out var token, out var binding, out var command ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The decrypted command routed from '{routed.Via[0]}' is malformed: it is refused." );
            return ValueTask.FromResult<byte[]?>( null );
        }
        proof.Token = token;
        proof.BindingSecretHash = binding;
        return ValueTask.FromResult<byte[]?>( command );
    }

    // The encrypted content: the token, the binding secret hash (empty when there is none) and the command.
    static byte[] Pack( string token, byte[]? binding, byte[] command )
    {
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( token );
            w.Write7BitEncodedInt( binding?.Length ?? 0 );
            if( binding != null ) w.Write( binding );
            w.Write7BitEncodedInt( command.Length );
            w.Write( command );
        }
        return m.ToArray();
    }

    static bool TryUnpack( byte[] plain, out string? token, out byte[]? binding, out byte[]? command )
    {
        token = null;
        binding = null;
        command = null;
        try
        {
            using var r = new BinaryReader( new MemoryStream( plain, writable: false ), Encoding.UTF8 );
            token = r.ReadString();
            var bindingLength = r.Read7BitEncodedInt();
            if( bindingLength < 0 || bindingLength > 1024 ) return false;
            binding = bindingLength > 0 ? r.ReadBytes( bindingLength ) : null;
            var commandLength = r.Read7BitEncodedInt();
            if( commandLength < 0 ) return false;
            command = r.ReadBytes( commandLength );
            return command.Length == commandLength
                   && (binding == null || binding.Length == bindingLength)
                   && r.BaseStream.Position == r.BaseStream.Length
                   && token.Length > 0;
        }
        catch( Exception ex ) when( ex is EndOfStreamException or FormatException )
        {
            return false;
        }
    }
}
