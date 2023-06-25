using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// The optional <see cref="IRemoteParty.DomainApplicationIdentity"/> when a remote defines a domain.
    /// </summary>
    sealed class DomainApplicationIdentity : ApplicationIdentityBase, IDomainApplicationIdentity
    {
        readonly RemoteParty _host;
        readonly IBridge _remotesChangedBridge;

        internal DomainApplicationIdentity( RemoteParty remote )
            : base( remote.Configuration.DomainConfiguration!, remote )            
        {
            Debug.Assert( remote.ApplicationIdentity is ApplicationIdentityService, "The host is a root." );
            _host = remote;
            // Creates a relay for RemotesChanged from this domain to the root ApplicationIdentityService's one.
            _remotesChangedBridge = _remotesChanged.CreateRelay( _host.ApplicationIdentity.ApplicationIdentityService._remotesChanged );
        }

        /// <summary>
        /// Gets the root application identity service.
        /// </summary>
        public ApplicationIdentityService ApplicationIdentityService => _host.ApplicationIdentity.ApplicationIdentityService;

        /// <summary>
        /// Gets the domain name: it is the <see cref="Host"/> domain name.
        /// </summary>
        public string DomainName => _host.Name;

        /// <summary>
        /// Gets the environment name: it is the <see cref="Host"/> environment name.
        /// </summary>
        public string EnvironmentName => _host.EnvironmentName;

        /// <summary>
        /// Gets the remote party that hosts this domain.
        /// </summary>
        public IRemoteParty Host => _host;

        /// <inheritdoc />
        public Task<IRemoteParty?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return AddDynamicRemotePartyAsync( monitor,
                                               configuration,
                                               false,
                                               ((ApplicationIdentityService)_host.ApplicationIdentity).Agent,
                                               _host.Name,
                                               _host.EnvironmentName );
        }

        internal async Task DestroyAsync( IActivityMonitor monitor )
        {
            // Signals the destruction completion of all sub remotes.
            // Clears its whole exposed remotes: when the event is raised, the destroyed
            // remotes must not appear in the Remotes.
            var subDomains = Interlocked.Exchange( ref _remotes, Array.Empty<RemoteParty>() );
            foreach( var r in subDomains )
            {
                var rI = Unsafe.As<IRemoteInternal>( r );
                Debug.Assert( rI.DestroyTCS != null );
                // This guaranties that an event is raised even for a remote in a destroyed remote.
                // Does this produces too much events (the bridge will relay the events to the root ApplicationIdentityService)?
                // It may be too verbose... but this is logically sound.
                await _remotesChanged.SafeRaiseAsync( monitor, r );
                r.DestroyTCS.SetResult();
            }
            _remotesChangedBridge.Dispose();
        }

        public override string ToString() => $"DomainApplicationIdentity of {_host.FullName.Path}";

    }
}
