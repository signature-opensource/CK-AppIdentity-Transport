using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Diagnostics.CodeAnalysis;

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
    {
        if( !IsAvailable )
        {
            logger.Warn( $"Token refused: the AuthCenter '{_authCenter}' of '{_owner}' has been destroyed." );
            return false;
        }
        // The driver checked that the AuthCenter has its keys.
        return _authCenter.GetRequiredFeature<IPartyKeys>().Verify( logger, ICrisAuthCenter.TokenPurpose, data, signature );
    }

    /// <summary>
    /// Reads a token issued by the Authentication Center for the <see cref="Owner"/>: its signature is verified
    /// (see <see cref="Verify"/>), then its audience (a token issued for another local party is refused).
    /// The authentication cannot outlive the token.
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="token">The token.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="info">The authentication on success.</param>
    /// <param name="sessionId">The session identifier on success.</param>
    /// <returns>True on success, false if the token is refused.</returns>
    public bool TryReadToken( IActivityLineEmitter logger,
                              string token,
                              DateTime utcNow,
                              [NotNullWhen( true )] out AuthenticationInfo? info,
                              [NotNullWhen( true )] out string? sessionId )
    {
        Throw.CheckNotNullArgument( token );
        return AuthCenterToken.TryRead( logger, this, _owner.FullName, token, utcNow, out info, out sessionId );
    }

    /// <summary>
    /// Overridden to return the Authentication Center and its owner.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => IsLocal ? $"AuthCenter '{_owner}' (local)" : $"AuthCenter '{_authCenter}' (remote of '{_owner}')";
}
