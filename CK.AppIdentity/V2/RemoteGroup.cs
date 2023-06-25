using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.Hosting;
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
        readonly IBridge _remotesChangedBridge;

        internal RemoteGroup( RemoteCollectionConfiguration configuration, RemoteCollection owner )
            : base( configuration, owner.ApplicationIdentityService )
        {
            _remote = new RemoteImpl( owner, configuration.Configuration );
            // Creates a relay for RemotesChanged from this group to the owner's one.
            _remotesChangedBridge = _remotesChanged.CreateRelay( owner._remotesChanged );
        }

        public RemoteCollection Owner => _remote.Owner;

        public bool IsDynamic => _remote.IsDynamic;

        public bool IsDestroyed => _remote.IsDestroyed;

        public bool IsRooted => _remote.IsRooted;

        public TaskCompletionSource? DestroyTCS => _remote.DestroyTCS;

        public Task DestroyAsync() => _remote.DestroyAsync( this );

        public bool SetDestroyed() => _remote.SetDestroyed( this );

        void IRemoteInternal.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, this );

        internal async Task DestroyAsync( IActivityMonitor monitor )
        {
            // Signals the destruction completion of all subordinate remotes.
            // Clears its whole exposed remotes: when the event is raised, the destroyed
            // remotes must not appear in the Remotes.
            var remotes = Interlocked.Exchange( ref _remotes, Array.Empty<RemoteParty>() );
            foreach( var r in remotes )
            {
                var rI = Unsafe.As<IRemoteInternal>( r );
                Debug.Assert( rI.DestroyTCS != null );
                // This guaranties that an event is raised even for a remote in a destroyed remote.
                // Does this produces too much events (the bridge will relay the events to the root ApplicationIdentityService)?
                // It may be too verbose... but this is logically sound.
                await _remotesChanged.SafeRaiseAsync( monitor, r );
                rI.DestroyTCS.SetResult();
            }
            _remotesChangedBridge.Dispose();
        }

    }
}
