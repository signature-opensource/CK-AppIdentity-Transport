using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The <see cref="ICrisAuthCenter"/> feature. A single instance is shared by a <see cref="ILocalParty"/> and
/// all its <see cref="ILocalParty.Remotes"/> that allow the "AuthCenter" feature.
/// </summary>
public sealed class CrisAuthCenter : ICrisAuthCenter
{
    readonly ILocalParty _owner;
    readonly IParty _authCenter;
    readonly LocalAuthCenter? _local;

    internal CrisAuthCenter( ILocalParty owner, IParty authCenter, LocalAuthCenter? local )
    {
        Throw.DebugAssert( authCenter == owner || (authCenter is IRemoteParty r && r.Owner == owner) );
        Throw.DebugAssert( (local != null) == (authCenter == owner) );
        _owner = owner;
        _authCenter = authCenter;
        _local = local;
    }

    /// <summary>
    /// Gets the local party for which <see cref="AuthCenter"/> is the Authentication Center.
    /// </summary>
    public ILocalParty Owner => _owner;

    /// <inheritdoc />
    public IParty AuthCenter => _authCenter;

    /// <summary>
    /// Gets whether the Authentication Center is the <see cref="Owner"/> itself: this application is the
    /// Authentication Center of the local party.
    /// </summary>
    public bool IsLocal => _local != null;

    /// <summary>
    /// Gets the local Authentication Center (its settings, its sessions, the signing of its tokens) when <see cref="IsLocal"/> is true.
    /// </summary>
    public LocalAuthCenter? Local => _local;

    /// <summary>
    /// Gets whether the Authentication Center can be used. This is false when the Authentication Center
    /// is a remote that has been destroyed: authentication is unavailable for the <see cref="Owner"/> (features
    /// cannot be removed, this feature stays and fails closed).
    /// </summary>
    public bool IsAvailable => !(_authCenter is IRemoteParty r && r.IsDestroyed);

    /// <inheritdoc />
    public bool Verify( IActivityLineEmitter logger, ReadOnlySpan<byte> data, in ApplicationSignature signature )
        => Check( logger, data, signature ) == SignatureVerdict.Valid;

    /// <inheritdoc />
    public SignatureVerdict Check( IActivityLineEmitter logger, ReadOnlySpan<byte> data, in ApplicationSignature signature )
    {
        if( !IsAvailable )
        {
            logger.Warn( $"Token refused: the AuthCenter '{_authCenter}' of '{_owner}' has been destroyed." );
            return SignatureVerdict.Refused;
        }
        // The driver checked that the AuthCenter has its keys.
        return _authCenter.GetRequiredFeature<IPartyKeys>().Check( logger, ICrisAuthCenter.TokenPurpose, data, signature );
    }

    /// <summary>
    /// The maximal time <see cref="ReadTokenAsync"/> waits for the key events of a remote Authentication Center: 2 seconds.
    /// </summary>
    public static readonly TimeSpan KeyEventsTimeout = TimeSpan.FromSeconds( 2 );

    /// <summary>
    /// Reads a token issued by the Authentication Center: its signature is verified (see <see cref="Check"/>), then its
    /// expiration and its audience: the <see cref="AuthCenter"/> party (a token issued by another Authentication Center, of
    /// another tenant domain for instance, is refused). The authentication cannot outlive the token.
    /// <para>
    /// For a remote Authentication Center, when the signature is refused because its issuer is not known here (it rotated
    /// its key and its key events, normally pushed, have not been received), the key events are requested (at most
    /// <see cref="KeyEventsTimeout"/>) and the token is read again, once.
    /// </para>
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="token">The token.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The authentication and the session identifier, or null if the token is refused.</returns>
    public async ValueTask<(AuthenticationInfo Info, string SessionId)?> ReadTokenAsync( IActivityLineEmitter logger, string token, DateTime utcNow )
    {
        Throw.CheckNotNullArgument( token );
        var verdict = AuthCenterToken.Read( logger, this, _authCenter.FullName, token, utcNow, out var info, out var sessionId );
        if( verdict == SignatureVerdict.UnknownIssuer
            && _authCenter.GetFeature<TransportFeature>() is TransportFeature transport
            && await transport.RequestKeyEventsAsync( KeyEventsTimeout ).ConfigureAwait( false ) )
        {
            verdict = AuthCenterToken.Read( logger, this, _authCenter.FullName, token, utcNow, out info, out sessionId );
        }
        return verdict == SignatureVerdict.Valid ? (info!, sessionId!) : null;
    }

    /// <summary>
    /// Overridden to return the Authentication Center and its owner.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => IsLocal ? $"AuthCenter '{_owner}' (local)" : $"AuthCenter '{_authCenter}' (remote of '{_owner}')";
}
