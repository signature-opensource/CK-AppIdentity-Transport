using CK.Core;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    sealed class RemoteParty : ApplicationIdentityParty, IRemoteParty, IOwnedPartyInternal
    {
        LocalParty _owner;
        TaskCompletionSource? _destroyTCS;
        int _isDestroyed;
        readonly bool _isDynamic;

        internal RemoteParty( RemotePartyConfiguration configuration, LocalParty owner, bool isDynamic )
            : base( configuration, owner.ApplicationIdentityService )
        {
            _owner = owner;
            _isDynamic = isDynamic;
        }

        public new RemotePartyConfiguration Configuration => Unsafe.As<RemotePartyConfiguration>( _configuration );

        public bool IsExternalParty => Configuration.IsExternalParty;

        public string? Address => Configuration.Address;

        public bool IsDynamic => _isDynamic;

        public bool IsDestroyed => _isDestroyed != 0;

        ILocalParty IOwnedParty.Owner => _owner;

        public LocalParty Owner => _owner;

        public Task DestroyAsync()
        {
            SetDestroyed();
            Throw.DebugAssert( _destroyTCS != null );
            return _destroyTCS.Task;
        }

        public bool SetDestroyed()
        {
            Throw.CheckState( IsDynamic );
            return DoSetDestroyed( true );
        }

        internal bool DoSetDestroyed( bool isTop )
        {
            if( Interlocked.CompareExchange( ref _isDestroyed, 1, 0 ) == 0 )
            {
                _destroyTCS = new TaskCompletionSource();
                if( isTop ) Owner.ApplicationIdentityService.Agent.OnDestroy( this );
                return true;
            }
            return false;
        }

        internal override async ValueTask OnShutdownOrDestroyedAsync( IActivityMonitor monitor, bool isDestroyed )
        {
            await base.OnShutdownOrDestroyedAsync( monitor, isDestroyed ).ConfigureAwait( false );
            if( isDestroyed )
            {
                Debug.Assert(_destroyTCS != null );
                _destroyTCS.SetResult();
            }
        }
    }
}
