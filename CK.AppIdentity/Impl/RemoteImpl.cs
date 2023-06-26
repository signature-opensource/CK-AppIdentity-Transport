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
        public readonly IRemoteOwnerInternal Owner;
        public TaskCompletionSource? DestroyTCS;
        int _isDestroyed;
        public readonly bool IsDynamic;

        public readonly bool IsDestroyed => _isDestroyed != 0;

        public RemoteImpl( IRemoteOwnerInternal owner, ImmutableConfigurationSection configuration )
        {
            Owner = owner;
            IsDynamic = ReferenceEquals( configuration.Key, "Dynamic" );
            _isDestroyed = 0;
            DestroyTCS = null;
        }

        public bool SetDestroyed( IRemoteInternal @this )
        {
            Throw.CheckState( IsDynamic );
            return DoSetDestroyed( true, @this );
        }

        public Task DestroyAsync( IRemoteInternal @this )
        {
            SetDestroyed( @this );
            Debug.Assert( DestroyTCS != null );
            return DestroyTCS.Task;
        }

        internal bool DoSetDestroyed( bool isTop, IRemoteInternal @this )
        {
            if( Interlocked.CompareExchange( ref _isDestroyed, 1, 0 ) == 0 )
            {
                DestroyTCS = new TaskCompletionSource();
                // We set the destroy flag and tcs on subordinates but we
                // trigger the agent on the destroyed root so that the feature drivers
                // see the "destruction" the same as the "initialization".
                if( @this is PartyGroup composite )
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
                if( isTop ) Owner.ApplicationIdentityService.Agent.OnDestroy( @this );
                return true;
            }
            return false;
        }

    }
}
