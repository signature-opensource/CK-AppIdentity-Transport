using CK.IO.Authentication;
using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.IO.AuthCenter;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The feature of a local party whose Authentication Center is a remote party: this application is a remote of it.
/// Added by the <see cref="RemoteAuthCenterFeatureDriver"/>.
/// </summary>
public sealed class RemoteAuthCenter : IAuthCenterProofChecker
{
    /// <summary>
    /// The maximal time to wait for the remote Authentication Center: 30 seconds.
    /// </summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds( 30 );

    readonly CrisAuthCenter _center;
    // The verified encryption key of the Authentication Center (as published), until the expiration of its signature.
    (PartyEncryptionKey Published, byte[] Spki, DateTime Expires)? _encryptionKey;

    internal RemoteAuthCenter( CrisAuthCenter center )
    {
        Throw.DebugAssert( center.AuthCenter is IRemoteParty );
        _center = center;
    }

    /// <summary>
    /// Gets the shared <see cref="CrisAuthCenter"/> feature: its <see cref="CrisAuthCenter.AuthCenter"/> is the remote
    /// Authentication Center.
    /// </summary>
    public CrisAuthCenter Center => _center;

    /// <summary>
    /// Gets the current encryption key of the Authentication Center: the one its party publishes in its description (see
    /// <see cref="PartyDescription.EncryptionKey"/>), whose signature is verified (with the same safety net as the tokens).
    /// The verified key is cached until it changes or expires.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>The SubjectPublicKeyInfo of the key, or null if it cannot be obtained (the reason is logged).</returns>
    internal async ValueTask<byte[]?> GetEncryptionKeyAsync( IActivityMonitor monitor )
    {
        var published = _center.AuthCenter.Description.EncryptionKey;
        if( published == null )
        {
            monitor.Warn( $"The AuthCenter '{_center.AuthCenter}' publishes no encryption key (it is not connected yet, or it has no key management)." );
            return null;
        }
        var cached = _encryptionKey;
        if( cached.HasValue
            && cached.Value.Published.Equals( published )
            && cached.Value.Expires - TimeSpan.FromMinutes( 1 ) > DateTime.UtcNow )
        {
            return cached.Value.Spki;
        }
        if( !ApplicationSignature.TryRead( published.Signature.Span, out var signature )
            || await _center.CheckWithKeyEventsAsync( monitor, PartyEncryption.KeyPurpose, published.PublicKey.ToArray(), signature ).ConfigureAwait( false ) != SignatureVerdict.Valid )
        {
            monitor.Warn( $"The encryption key of the AuthCenter '{_center.AuthCenter}' is refused." );
            return null;
        }
        var spki = published.PublicKey.ToArray();
        _encryptionKey = (published, spki, signature.Expiration);
        return spki;
    }

    /// <summary>
    /// Overridden to return the Authentication Center and its owner.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => _center.ToString();

    /// <summary>
    /// Checks a user's proof relayed by another party (see <see cref="IAuthCenterProofChecker"/>): the token is read here
    /// first, with the keys of the Authentication Center (a garbage token, an expired one, a wrong binding secret are
    /// refused without asking), then the Authentication Center is asked whether its session is alive and is still the
    /// token's (<see cref="IVerifyCallerProofCommand"/>). It can't be reached: the proof is not verified (fail closed).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <returns>The proved identity, or null when the proof is not valid (the reason is logged).</returns>
    public async ValueTask<AuthenticationInfo?> CheckProofAsync( IActivityMonitor monitor, string token, byte[] bindingSecretHash )
    {
        var read = await _center.ReadProofAsync( monitor, token, bindingSecretHash, DateTime.UtcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( "An invalid user's proof is ignored." );
            return null;
        }
        return await CheckLivenessAsync( monitor, token, read, null ).ConfigureAwait( false );
    }

    /// <summary>
    /// Asks the Authentication Center whether the session of a proof that has been read here is alive and is still the
    /// token's (<see cref="IVerifyCallerProofCommand"/>) and, for the proof of a routed command, whether the session party
    /// sealed it for this local party (the Authentication Center has its keys). It can't be reached: the proof is not
    /// verified (fail closed).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="read">The content of the token, read with its binding secret.</param>
    /// <param name="seal">The seal of the routed command that carried the proof, null for a proof received directly.</param>
    /// <returns>The proved identity, or null when the session ended or changed, the seal is invalid, or it can't be checked (the reason is logged).</returns>
    public async ValueTask<AuthenticationInfo?> CheckLivenessAsync( IActivityMonitor monitor, string token, AuthCenterTokenContent read, RoutedProofSeal? seal )
    {
        Throw.CheckNotNullArgument( token );
        Throw.CheckNotNullArgument( read );
        var bindingSecretHash = read.BindingSecretHash;
        var center = (IRemoteParty)_center.AuthCenter;
        var channel = center.GetFeature<CrisChannelFeature>();
        if( channel == null )
        {
            monitor.Warn( $"No Cris channel to the AuthCenter '{center}': a user's proof can't be verified, it is ignored." );
            return null;
        }
        IAuthenticationInfoPoco? answer;
        try
        {
            var command = channel.PocoDirectory.Create<IVerifyCallerProofCommand>( c =>
            {
                c.Token = token;
                c.BindingSecretHash = bindingSecretHash;
                if( seal != null )
                {
                    c.RoutedSeal = seal.Header;
                    c.RoutedPayloadDigest = seal.PayloadDigest;
                    c.RoutedSignature = seal.Signature;
                }
            } );
            answer = await channel.SendCommand( monitor, command )
                                  .WithResult<IAuthenticationInfoPoco?>().Result.WaitAsync( Timeout ).ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to ask the AuthCenter '{center}' to verify a user's proof: it is ignored.", ex );
            return null;
        }
        if( answer == null )
        {
            monitor.Warn( seal == null
                            ? $"The AuthCenter '{center}' refused a user's proof: its session ended or changed."
                            : $"The AuthCenter '{center}' refused the user's proof of a routed command: its session ended or changed, or its seal is invalid." );
            return null;
        }
        return AuthCenterProofVerifier.FromAuthCenterAnswer( answer, DateTime.UtcNow );
    }
}
