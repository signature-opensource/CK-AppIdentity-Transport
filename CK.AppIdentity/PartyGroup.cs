using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    public sealed class PartyGroup : ApplicationIdentityObject, IRemote, IRemoteInternal, IRemoteOwnerInternal
    {
        // RemoteGroup is a group of Remotes (it owns remotes). 
        RemoteOwnerImpl _remotes;
        // RemoteGroup is a Remote (it is owned).
        RemoteImpl _remote;
        // Changes in contained remotes are propagated to this remote owner).
        readonly IBridge _remotesChangedBridge;

        internal PartyGroup( PartyGroupConfiguration configuration, IRemoteOwnerInternal owner )
            : base( configuration, owner.ApplicationIdentityService )
        {
            _remote = new RemoteImpl( owner, configuration.Configuration );
            _remotes = new RemoteOwnerImpl( this );
            _remotes.Initialize( this, configuration.Parties );
            // Creates a relay for RemotesChanged from this group to the owner's one.
            _remotesChangedBridge = _remotes.RemotesChanged.CreateRelay( owner.RemotesChanged );
        }

        /// <summary>
        /// Gets the <see cref="PartyGroupConfiguration"/> object.
        /// </summary>
        public new PartyGroupConfiguration Configuration => Unsafe.As<PartyGroupConfiguration>( _configuration );

        /// <inheritdoc />
        public IRemoteOwner Owner => _remote.Owner;

        IRemoteOwnerInternal IRemoteInternal.Owner => _remote.Owner;

        /// <inheritdoc />
        public bool IsDynamic => _remote.IsDynamic;

        /// <inheritdoc />
        public bool IsDestroyed => _remote.IsDestroyed;

        /// <inheritdoc />
        public TaskCompletionSource? DestroyTCS => _remote.DestroyTCS;

        /// <inheritdoc />
        public Task DestroyAsync() => _remote.DestroyAsync( this );

        /// <inheritdoc />
        public bool SetDestroyed() => _remote.SetDestroyed( this );

        void IRemoteInternal.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, this );

        /// <inheritdoc />
        public IReadOnlyCollection<IRemote> Remotes => _remotes.Remotes;

        /// <inheritdoc />
        public IEnumerable<IRemote> AllRemotes => _remotes.AllRemotes;

        /// <inheritdoc />
        public PerfectEvent<IRemote> RemotesChanged => _remotes.RemotesChanged.PerfectEvent;

        /// <inheritdoc />
        public Task<IRemote?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return _remotes.AddDynamicRemotePartyAsync( this, monitor, configuration, ApplicationIdentityService.Agent, Configuration.DomainName, Configuration.EnvironmentName );
        }

        PerfectEventSender<IRemote> IRemoteOwnerInternal.RemotesChanged => _remotes.RemotesChanged;

        void IRemoteOwnerInternal.RemoveDestroyed( IRemote destroyed ) => _remotes.RemoveDestroyed( destroyed );

        void IRemoteOwnerInternal.OnSuccessAddRemoteAsync( IActivityMonitor monitor, IRemote r ) => _remotes.OnSuccessAddRemoteAsync( monitor, r );

        internal async Task DestroyAsync( IActivityMonitor monitor )
        {
            // Signals the destruction completion of all subordinate remotes.
            // Clears its whole exposed remotes: when the event is raised, the destroyed
            // remotes must not appear in the Remotes.
            var remotes = _remotes.ClearRemotes();
            foreach( var r in remotes )
            {
                var rI = Unsafe.As<IRemoteInternal>( r );
                Debug.Assert( rI.DestroyTCS != null );
                // This guaranties that an event is raised even for a remote in a destroyed remote.
                // Does this produces too much events (the bridge will relay the events to the root ApplicationIdentityService)?
                // It may be too verbose... but this is logically sound.
                await _remotes.RemotesChanged.SafeRaiseAsync( monitor, r );
                rI.DestroyTCS.SetResult();
            }
            _remotesChangedBridge.Dispose();
        }

        public override string ToString() => $"Group '{Configuration.DomainName}/{Configuration.EnvironmentName}'";
    }
}
