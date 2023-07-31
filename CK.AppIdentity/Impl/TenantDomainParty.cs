using CK.Core;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    sealed class TenantDomainParty : LocalParty, ITenantDomainParty, IOwnedPartyInternal
    {
        TaskCompletionSource? _destroyTCS;
        int _isDestroyed;
        readonly bool _isDynamic;

        internal TenantDomainParty( TenantDomainPartyConfiguration configuration, bool isDynamic, ApplicationIdentityService root )
            : base( configuration,
                    configuration.Remotes,
                    isDynamic,
                    root )
        {
            _isDynamic = isDynamic;
        }

        public new TenantDomainPartyConfiguration Configuration => Unsafe.As<TenantDomainPartyConfiguration>( _configuration );

        ILocalParty IOwnedParty.Owner => ApplicationIdentityService;

        IApplicationIdentityService ITenantDomainParty.Owner => ApplicationIdentityService;

        public LocalParty Owner => ApplicationIdentityService;

        public bool IsDynamic => _isDynamic;

        public bool IsDestroyed => _isDestroyed != 0;

        public Task DestroyAsync()
        {
            SetDestroyed();
            Throw.DebugAssert( _destroyTCS != null );
            return _destroyTCS.Task;
        }

        public bool SetDestroyed()
        {
            Throw.CheckState( _isDynamic );
            if( Interlocked.CompareExchange( ref _isDestroyed, 1, 0 ) == 0 )
            {
                _destroyTCS = new TaskCompletionSource();
                foreach( var r in _remotes )
                {
                    // Use the CAS check on destroy to prevent any
                    // duplicate request but skip the IsDynamic check.
                    r.DoSetDestroyed( false );
                }
                Owner.ApplicationIdentityService.Agent.OnDestroy( this );
                return true;
            }
            return false;
        }

        internal async Task OnDestroyedAsync( IActivityMonitor monitor )
        {
            // Signals the destruction completion of all subordinate remotes.
            // Clears the exposed remotes: when the event is raised, the destroyed
            // remotes must not appear in the Remotes.
            var remotes = Interlocked.Exchange( ref _remotes, Array.Empty<RemoteParty>() );
            foreach( var r in remotes )
            {
                // This raises an event for each remote.
                // Does this produces too much events (the bridge will relay the events to the root ApplicationIdentityService)?
                // It may be too verbose... but this is logically sound.
                await _remotesChanged.SafeRaiseAsync( monitor, r ).ConfigureAwait( false );
                await r.OnShutdownOrDestroyedAsync( monitor, true ).ConfigureAwait( false );
            }
        }

        internal override async ValueTask OnShutdownOrDestroyedAsync( IActivityMonitor monitor, bool isDestroyed )
        {
            _remotesChangedBridge.Dispose();
            await base.OnShutdownOrDestroyedAsync( monitor, isDestroyed ).ConfigureAwait( false );
            if( isDestroyed )
            {
                Throw.DebugAssert( _destroyTCS != null );
                _destroyTCS.SetResult();
            }
        }
    }
}
