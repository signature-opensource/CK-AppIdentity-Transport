using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    struct RemoteOwnerImpl
    {
        IRemote[] _remotes;
        public readonly PerfectEventSender<IRemote> RemotesChanged;

        /// <summary>
        /// Requires a 2-steps initialization: created remotes needs an acces to
        /// the RemotesChanged through the IRemoteOwnerInternal.
        /// </summary>
        /// <param name="this">Fake parameter (but the actual owner of this implementation for coherency).</param>
        public RemoteOwnerImpl( IRemoteOwnerInternal @this )
        {
            RemotesChanged = new PerfectEventSender<IRemote>();
            _remotes = Array.Empty<IRemote>();
        }

        public void Initialize( IRemoteOwnerInternal @this, IReadOnlyCollection<ApplicationIdentityObjectConfiguration> remotes )
        {
            var r = new IRemote[remotes.Count];
            int i = 0;
            foreach( var c in remotes )
            {
                r[i++] = CreateFrom( @this, c );
            }
            _remotes = r;
        }

        static IRemoteInternal CreateFrom( IRemoteOwnerInternal @this, ApplicationIdentityObjectConfiguration c )
        {
            return c switch
            {
                RemotePartyConfiguration p => new RemoteParty( p, @this ),
                PartyGroupConfiguration g => new PartyGroup( g, @this ),
                ApplicationIdentityObjectConfiguration e => new ExternalParty( e, @this ),
                _ => Throw.NotSupportedException<IRemoteInternal>()
            };
        }

        public IReadOnlyCollection<IRemote> Remotes => _remotes;

        public IEnumerable<IRemote> AllRemotes
        {
            get
            {
                foreach( var r in _remotes )
                {
                    yield return r;
                    if( r is PartyGroup g )
                    {
                        foreach( var rS in g.AllRemotes )
                        {
                            yield return rS;
                        }
                    }
                }
            }
        }

        public async Task<IRemote?> AddDynamicRemotePartyAsync( IRemoteOwnerInternal @this,
                                                                IActivityMonitor monitor,
                                                                Action<MutableConfigurationSection> configuration,
                                                                AppIdentityAgent agent,
                                                                string thisDomainName,
                                                                string thisEnvironmentName )
        {
            Throw.CheckNotNullArgument( configuration );
            var c = @this.Configuration.CreateDynamicRemoteConfiguration( monitor, configuration, thisDomainName, thisEnvironmentName );
            if( c == null ) return null;
            Debug.Assert( c.Configuration.Key == "Dynamic" );
            var r = CreateFrom( @this, c );
            if( !await agent.InitializeDynamicRemoteAsync( r ) ) return null;
            // The remote is InterlockedAdded to the _remotes only on success (and in the second
            // round of OnSuccess trampoline) by OnSuccessAddRemote below.
            return r;
        }

        internal Task OnSuccessAddRemoteAsync( IActivityMonitor monitor, IRemote r )
        {
            Util.InterlockedAdd( ref _remotes, r );
            if( r is PartyGroup group )
            {
                // This is to publish "new remotes" events in the root ApplicationIndentityService.RemotesChanged event
                // so that by subscribing to this event, the whole structure change can be tracked.
                return OnSuccessAddRemoteDomainAsync( monitor, r, group );
            }
            return RemotesChanged.RaiseAsync( monitor, r );
        }

        async Task OnSuccessAddRemoteDomainAsync( IActivityMonitor monitor, IRemote r, IRemoteOwnerInternal group )
        {
            // Makes the root appear before its children.
            await RemotesChanged.RaiseAsync( monitor, r );
            foreach( var sub in group.Remotes )
            {
                await group.RemotesChanged.SafeRaiseAsync( monitor, sub );
            }
        }

        internal void RemoveDestroyed( IRemote destroyed )
        {
            Util.InterlockedRemove( ref _remotes, destroyed );
        }

        internal IRemote[] ClearRemotes()
        {
            return Interlocked.Exchange( ref _remotes, Array.Empty<RemoteParty>() );
        }
    }
}
