using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The statement of the Authentication Center that a routed user's proof is valid (the answer to an
/// <c>IVerifyRoutedProofQCommand</c>): it signs (<see cref="Purpose"/>) the destination, the nonce of the asking party,
/// the digest of the token and of the seal. The asking party verifies it with the keys of the Authentication Center (its
/// trust anchor): the answer crosses hops, a hop can withhold it, not forge it.
/// <para>
/// The proof itself (the token and the hash of the binding secret) crosses the hops encrypted for the Authentication
/// Center (<see cref="EncryptProof"/>): a hop never holds it.
/// </para>
/// </summary>
public static class AuthCenterProofStatement
{
    /// <summary>
    /// The purpose of the signature of a statement by the Authentication Center.
    /// </summary>
    public const string Purpose = "CK.AuthCenter.ProofStatement";

    /// <summary>
    /// The size of the nonce chosen by the asking party.
    /// </summary>
    public const int NonceSize = 16;

    /// <summary>
    /// The lifetime of a statement: 1 minute (it is checked at once by the asking party).
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes( 1 );

    // The associated data of an encrypted proof.
    static readonly byte[] _proofContext = "CK.AuthCenter.VerifyRoutedProof"u8.ToArray();

    /// <summary>
    /// Encrypts the user's proof for the Authentication Center (see <see cref="PartyEncryption.Encrypt"/>), with the
    /// destination and the nonce as associated data.
    /// </summary>
    /// <param name="authCenterKey">The encryption key of the Authentication Center (SubjectPublicKeyInfo).</param>
    /// <param name="destination">The full name of the asking party.</param>
    /// <param name="nonce">The nonce chosen by the asking party.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The encrypted proof.</returns>
    public static byte[] EncryptProof( ReadOnlySpan<byte> authCenterKey, string destination, ReadOnlySpan<byte> nonce, string token, byte[] bindingSecretHash, DateTime utcNow )
    {
        Throw.CheckNotNullOrEmptyArgument( token );
        Throw.CheckNotNullArgument( bindingSecretHash );
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( token );
            w.Write7BitEncodedInt( bindingSecretHash.Length );
            w.Write( bindingSecretHash );
        }
        var plain = m.ToArray();
        try
        {
            return PartyEncryption.Encrypt( authCenterKey, plain, GetProofContext( destination, nonce ), utcNow, out _ );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( plain );
        }
    }

    /// <summary>
    /// Decrypts a user's proof encrypted by <see cref="EncryptProof"/>, on the Authentication Center. The reason of a failure is logged.
    /// </summary>
    /// <param name="logger">Receives the reason of a failure.</param>
    /// <param name="keys">The keys of the Authentication Center.</param>
    /// <param name="encrypted">The encrypted proof.</param>
    /// <param name="destination">The full name of the asking party.</param>
    /// <param name="nonce">The nonce chosen by the asking party.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="token">The user's token on success.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret on success.</param>
    /// <returns>True on success.</returns>
    public static bool TryDecryptProof( IActivityLineEmitter logger,
                                        ILocalKeys keys,
                                        ReadOnlySpan<byte> encrypted,
                                        string destination,
                                        ReadOnlySpan<byte> nonce,
                                        DateTime utcNow,
                                        out string? token,
                                        out byte[]? bindingSecretHash )
    {
        token = null;
        bindingSecretHash = null;
        if( !PartyEncryption.TryDecrypt( logger,
                                         encrypted,
                                         id => keys.FindEncryptionKey( id, utcNow ),
                                         GetProofContext( destination, nonce ),
                                         utcNow,
                                         RoutedCommandSeal.Lifetime + RoutedCommandSeal.ClockSkew,
                                         out var plain,
                                         out _ ) )
        {
            return false;
        }
        try
        {
            using var r = new BinaryReader( new MemoryStream( plain!, writable: false ), Encoding.UTF8 );
            var t = r.ReadString();
            var length = r.Read7BitEncodedInt();
            if( t.Length > 0 && length > 0 && length <= r.BaseStream.Length - r.BaseStream.Position )
            {
                var b = r.ReadBytes( length );
                if( r.BaseStream.Position == r.BaseStream.Length )
                {
                    token = t;
                    bindingSecretHash = b;
                    return true;
                }
            }
        }
        catch( Exception ex ) when( ex is EndOfStreamException or FormatException )
        {
        }
        finally
        {
            CryptographicOperations.ZeroMemory( plain );
        }
        logger.Warn( "The encrypted user's proof is malformed." );
        return false;
    }

    static byte[] GetProofContext( string destination, ReadOnlySpan<byte> nonce )
    {
        Throw.CheckNotNullOrEmptyArgument( destination );
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( _proofContext );
            w.Write( destination );
            w.Write( (byte)nonce.Length );
            w.Write( nonce );
        }
        return m.ToArray();
    }

    /// <summary>
    /// Gets the data signed by a statement.
    /// </summary>

    /// <param name="destination">The full name of the asking party (the destination of the routed command).</param>
    /// <param name="nonce">The nonce chosen by the asking party.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="seal">The seal of the routed command.</param>
    /// <returns>The signed data.</returns>
    public static byte[] GetSignedData( string destination, ReadOnlySpan<byte> nonce, string token, RoutedProofSeal seal )
    {
        Throw.CheckNotNullOrEmptyArgument( destination );
        Throw.CheckNotNullArgument( token );
        Throw.CheckNotNullArgument( seal );
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( destination );
            w.Write( (byte)nonce.Length );
            w.Write( nonce );
            w.Write( SHA256.HashData( Encoding.UTF8.GetBytes( token ) ) );
            w.Write( SHA256.HashData( seal.Header ) );
            w.Write( (byte)seal.PayloadDigest.Length );
            w.Write( seal.PayloadDigest );
        }
        return m.ToArray();
    }
}
