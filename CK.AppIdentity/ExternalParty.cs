using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// An external remote is defined in the "Undefined" domain name.
    /// Its configuration is the base <see cref="ApplicationIdentityObjectConfiguration"/>: it is up to the features
    /// to match any configuration key (like a "GitHubApi" section) and plug features on the remote.
    /// </summary>
    public sealed class ExternalParty : ApplicationIdentityObject, IRemote, IRemoteInternal
    {
        RemoteImpl _remote;

        internal ExternalParty( ApplicationIdentityObjectConfiguration configuration, IRemoteOwnerInternal owner )
            : base( configuration, owner.ApplicationIdentityService )
        {
            _remote = new RemoteImpl( owner, configuration.Configuration );
        }

        /// <inheritdoc />
        public bool IsDynamic => _remote.IsDynamic;

        /// <inheritdoc />
        public bool IsDestroyed => _remote.IsDestroyed;

        /// <inheritdoc />
        public IRemoteOwner Owner => _remote.Owner;

        IRemoteOwnerInternal IRemoteInternal.Owner => _remote.Owner;

        /// <inheritdoc />
        public Task DestroyAsync() => _remote.DestroyAsync( this );

        /// <inheritdoc />
        public bool SetDestroyed() => _remote.SetDestroyed( this );

        void IRemoteInternal.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, this );

        TaskCompletionSource? IRemoteInternal.DestroyTCS => _remote.DestroyTCS;
    }
}
