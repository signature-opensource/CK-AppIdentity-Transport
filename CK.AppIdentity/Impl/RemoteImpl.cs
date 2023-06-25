using CK.Core;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    struct RemoteImpl
    {
        public readonly RemoteCollection Owner;
        public TaskCompletionSource? DestroyTCS;
        int _isDestroyed;
        public readonly bool IsDynamic;

        public bool IsDestroyed => _isDestroyed != 0;

        public bool IsRooted => Owner is ApplicationIdentityService;

        public RemoteImpl( RemoteCollection domain, ImmutableConfigurationSection configuration )
        {
            Owner = domain;
            IsDynamic = ReferenceEquals( configuration.Key, "Dynamic" );
            _isDestroyed = 0;
            DestroyTCS = null;
        }

        public bool SetDestroyed( IRemoteInternal owner )
        {
            Throw.CheckState( IsDynamic );
            return DoSetDestroyed( true, owner );
        }

        public Task DestroyAsync( IRemoteInternal owner )
        {
            SetDestroyed( owner );
            Debug.Assert( DestroyTCS != null );
            return DestroyTCS.Task;
        }

        internal bool DoSetDestroyed( bool isTop, IRemoteInternal owner )
        {
            if( Interlocked.CompareExchange( ref _isDestroyed, 1, 0 ) == 0 )
            {
                DestroyTCS = new TaskCompletionSource();
                // We set the destroy flag and tcs on subordinates but we
                // trigger the agent on the destroyed root so that the feature drivers
                // see the "destruction" the same as the "initialization".
                if( owner is RemoteGroup composite )
                {
                    // Immediately condemns the child remotes and ask to handle
                    // their destruction first.
                    // They know that their host is destroyed (we set the flag to enter this).
                    foreach( var r in composite.Remotes )
                    {
                        // Use the CAS check on destroy to prevent any
                        // duplicate request but skip the IsDynamic check.
                        ((IRemoteInternal)r).DoSetDestroyed( false );
                    }
                }
                if( isTop ) Owner.ApplicationIdentityService.Agent.OnDestroy( owner );
                return true;
            }
            return false;
        }

    }
}
