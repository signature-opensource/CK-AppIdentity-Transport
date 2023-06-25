using CK.Core;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    public sealed class RemoteParty : ApplicationIdentityParty, IRemote, IRemoteInternal
    {
        NormalizedPath _sharedStorePath;
        RemoteImpl _remote;

        internal RemoteParty( RemotePartyConfiguration configuration, IRemoteOwnerInternal owner )
            : base( configuration, owner.ApplicationIdentityService )
        {
            _remote = new RemoteImpl( owner, configuration.Configuration );
            _sharedStorePath = owner.ApplicationIdentityService.ComputeSharedStorePath( FullName );
            Directory.CreateDirectory( _sharedStorePath );
        }

        /// <summary>
        /// Gets the path to the directory of this party.
        /// </summary>
        public NormalizedPath SharedStorePath => _sharedStorePath;

        /// <summary>
        /// Gets the <see cref="RemotePartyConfiguration"/> object.
        /// </summary>
        public new RemotePartyConfiguration Configuration => Unsafe.As<RemotePartyConfiguration>( _configuration );

        /// <summary>
        /// Gets the address of this party.
        /// This is null if this application cannot reach the remote: this remote must be a server that accepts the remote as a client).
        /// </summary>
        public string? Address => Configuration.Address;

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
