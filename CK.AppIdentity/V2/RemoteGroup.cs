using CK.Core;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    public sealed class RemoteGroup : RemoteCollection, IRemote, IRemoteInternal
    {
        RemoteImpl _remote;

        internal RemoteGroup( RemoteCollectionConfiguration configuration, RemoteCollection owner )
            : base( configuration, owner.ApplicationIdentityService )
        {
            _remote = new RemoteImpl( owner, configuration.Configuration );
        }

        public RemoteCollection Owner => _remote.Owner;

        public bool IsDynamic => _remote.IsDynamic;

        public bool IsDestroyed => _remote.IsDestroyed;

        public bool IsRooted => _remote.IsRooted;

        public TaskCompletionSource? DestroyTCS => _remote.DestroyTCS;

        public Task DestroyAsync() => _remote.DestroyAsync( this );

        public bool SetDestroyed() => _remote.SetDestroyed( this );

        void IRemoteInternal.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, this );

    }
}
