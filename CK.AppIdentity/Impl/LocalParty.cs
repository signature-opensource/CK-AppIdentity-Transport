using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Common base for <see cref="ApplicationIdentityService"/> and <see cref="TenantDomainParty"/>.
    /// </summary>
    public abstract class LocalParty : ApplicationIdentityParty, ILocalParty
    {
        private protected RemoteParty[] _remotes;
        internal readonly PerfectEventSender<IRemoteParty> _remotesChanged;
        readonly NormalizedPath _privateStorePath;
        // Changes in contained remotes are propagated to the root AllPartyChanged event.
        private protected readonly IBridge _remotesChangedBridge;

        internal LocalParty( ApplicationIdentityPartyConfiguration configuration,
                             IEnumerable<RemotePartyConfiguration> remotes,
                             bool isDynamic,
                             ApplicationIdentityService? appIdentityService )
            : base( configuration, appIdentityService )
        {
            _remotesChanged = new PerfectEventSender<IRemoteParty>();
            _remotes = remotes.Select( c => new RemoteParty( c, this, isDynamic ) ).ToArray();
            // Creates a relay for RemotesChanged from this group to the root's AllPartyChanged event.
            // Chicken and Egg here: if we are the root, create the AllPartiesChanged event instance
            // and bridge it.
            // The ApplicationIdentityService constructor will get the IBridge.Target. 
            var bridgeTarget = appIdentityService?._allPartyChanged ?? new PerfectEventSender<IOwnedParty>();
            _remotesChangedBridge = _remotesChanged.CreateBridge( bridgeTarget!, Unsafe.As<IOwnedParty> );
            _privateStorePath = SharedStorePath.AppendPart( "$Local" );
        }

        /// <inheritdoc />
        public PerfectEvent<IRemoteParty> RemotesChanged => _remotesChanged.PerfectEvent;

        /// <inheritdoc />
        public IReadOnlyCollection<IRemoteParty> Remotes => _remotes;

        /// <inheritdoc />
        public NormalizedPath PrivateStorePath => _privateStorePath;

        /// <inheritdoc />
        public async Task<IReadOnlyCollection<IRemoteParty>?> AddMultipleRemotesAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return (await AddDynamicPartiesAsync( monitor, configuration, false, false, null ).ConfigureAwait(false))?.Remotes;
        }

        /// <inheritdoc />
        public async Task<IRemoteParty?> AddRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return (await AddDynamicPartiesAsync( monitor, configuration, true, false, null ).ConfigureAwait(false))?.Remotes.Single();
        }

        private protected async Task<AddedDynamicParties?> AddDynamicPartiesAsync( IActivityMonitor monitor,
                                                                                   Action<MutableConfigurationSection> configuration,
                                                                                   bool singleRemote,
                                                                                   bool singleTenant,
                                                                                   ApplicationIdentityService? withTenants )
        {
            Throw.CheckNotNullArgument( configuration );
            var c = Configuration.CreateDynamicRemoteConfiguration( monitor, configuration );
            if( c == null ) return null;
            if( c.Value.Count == 0 ) return new AddedDynamicParties( Array.Empty<RemoteParty>(), Array.Empty<TenantDomainParty>() );
            if( singleTenant )
            {
                if( c.Value.Tenants.Count > 1 || c.Value.Remotes.Count > 0 )
                {
                    Throw.ArgumentException( nameof( configuration ), $"A single tenant domain configuration is expected " +
                                                                      $"(found '{c.Value.Parties.Select( p => p.ToString() ).Concatenate( "', '" )}')." );
                }
            }
            if( singleRemote )
            {
                if( c.Value.Remotes.Count > 1 || c.Value.Tenants.Count > 0 )
                {
                    Throw.ArgumentException( nameof( configuration ), $"A single remote configuration is expected " +
                                                                      $"(found '{c.Value.Parties.Select( p => p.ToString() ).Concatenate( "', '" )}')." );
                }
            }
            if( withTenants == null )
            {
                if( c.Value.Tenants.Count > 0 )
                {
                    Throw.ArgumentException( nameof( configuration ), $"No tenant domain configuration is allowed " +
                                                                      $"(found '{c.Value.Tenants.Select( d => d.ToString() ).Concatenate( "', '" )}')." );
                }
            }
            RemoteParty[] r = c.Value.Remotes.Select( c => new RemoteParty( c, this, true ) ).ToArray();
            TenantDomainParty[] t = withTenants == null
                                    ? Array.Empty<TenantDomainParty>()
                                    : c.Value.Tenants.Select( c => new TenantDomainParty( c, true, withTenants ) ).ToArray();

            var added = new AddedDynamicParties( r, t );
            if( !await ApplicationIdentityService.Agent.InitializeDynamicPartiesAsync( added ).ConfigureAwait( false ) )
            {
                return null;
            }
            // The items are InterlockedAdded to the _remotes and service _domains only on success (and in the second
            // round of OnSuccess trampoline) by the agent (ApplicationIdentityService.OnCreatedAsync is called for each remote or domain).
            return added;
        }


        internal PerfectEventSender<IRemoteParty> RemotesChangedSender => _remotesChanged;

        internal Task OnDestroyedRemoteAsync( IActivityMonitor monitor, RemoteParty p )
        {
            Util.InterlockedRemove( ref _remotes, p );
            // It is the agent that eventually signals the destroyTCS.
            return _remotesChanged.RaiseAsync( monitor, p );
        }

        internal Task OnCreatedRemoteAsync( IActivityMonitor monitor, RemoteParty p )
        {
            Util.InterlockedAdd( ref _remotes, p );
            return _remotesChanged.RaiseAsync( monitor, p );
        }

    }
}
