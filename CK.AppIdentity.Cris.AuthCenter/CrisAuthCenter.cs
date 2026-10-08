using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The <see cref="ICrisAuthCenter"/> feature. A single instance is shared by a <see cref="ILocalParty"/> and
/// all its <see cref="ILocalParty.Remotes"/> that allow the "AuthCenter" feature.
/// </summary>
public sealed class CrisAuthCenter : ICrisAuthCenter
{
    readonly ILocalParty _owner;
    readonly IParty _authCenter;

    internal CrisAuthCenter( ILocalParty owner, IParty authCenter )
    {
        Throw.DebugAssert( authCenter == owner || (authCenter is IRemoteParty r && r.Owner == owner) );
        _owner = owner;
        _authCenter = authCenter;
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
    public bool IsLocal => _authCenter == _owner;

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
    /// Overridden to return the Authentication Center and its owner.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => IsLocal ? $"AuthCenter '{_owner}' (local)" : $"AuthCenter '{_authCenter}' (remote of '{_owner}')";
}
