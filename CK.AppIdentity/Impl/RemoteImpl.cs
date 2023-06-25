using CK.Core;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    struct RemoteImpl
    {
        public readonly ApplicationIdentityDomain Domain;
        public TaskCompletionSource? DestroyTCS;
        int _isDestroyed;
        public readonly bool IsDynamic;

        public bool IsDestroyed => _isDestroyed != 0;

        public RemoteImpl( ApplicationIdentityDomain domain, ImmutableConfigurationSection configuration )
        {
            Domain = domain;
            IsDynamic = ReferenceEquals( configuration.Key, "Dynamic" );
            _isDestroyed = 0;
            DestroyTCS = null;
        }

        public bool SetDestroyed( IRemote owner )
        {
            Throw.CheckState( IsDynamic );
            return DoSetDestroyed( true, owner );
        }

        public Task DestroyAsync( IRemote owner )
        {
            SetDestroyed( owner );
            Debug.Assert( DestroyTCS != null );
            return DestroyTCS.Task;
        }

        internal bool DoSetDestroyed( bool isTop, IRemote owner )
        {
            if( Interlocked.CompareExchange( ref _isDestroyed, 1, 0 ) == 0 )
            {
                DestroyTCS = new TaskCompletionSource();
                // We set the destroy flag and tcs on subordinates but we
                // trigger the agent on the destroyed root so that the feature drivers
                // see the "destruction" the same as the "initialization".
                if( owner is RemoteDomain domain )
                {
                    // Immediately condemns the child remotes and ask to handle
                    // their destruction first.
                    // They know that their host is destroyed (we set the flag to enter this).
                    domain.Local._isDestroyed = true;
                    foreach( var r in domain.Remotes )
                    {
                        // Use the CAS check on destroy to prevent any
                        // duplicate request but skip the IsDynamic check.
                        r.DoSetDestroyed( false );
                    }
                }
                if( isTop ) Domain.ApplicationIdentityService.Agent.OnDestroy( this );
                return true;
            }
            return false;
        }

    }
}
