using CK.Core;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading.Tasks;

namespace CK.AppIdentity.PocoChannel
{
    sealed class Server
    {
        List<IPEndPoint> _endpoints;

        public void EnsureListeningAddress( IPEndPoint listeningPoint )
        {
        }
    }

    public sealed class PocoChannelFeatureDriver : ApplicationIdentityFeatureDriver
    {
        [AllowNull]
        AppIdentityAgent _appIdentityAgent;
        [AllowNull]
        ConnectionManager _connectionManager;

        public PocoChannelFeatureDriver( ApplicationIdentityService s )
            : base( s, true )
        {
        }

        protected override Task<bool> InitializeAsync( IActivityMonitor monitor, AppIdentityAgent appIdentityAgent )
        {
            _appIdentityAgent = appIdentityAgent;
            _connectionManager = new ConnectionManager( appIdentityAgent );
            bool success = _connectionManager.Start();
            if( !success )
            {
                monitor.Error( "Unable to start the connection manager." );
            }
            foreach( var r in ApplicationIdentity.Remotes )
            {
                bool isAllowed = r.Configuration.IsAllowedFeature( FeatureName, IsRootAllowed );
                if( r.DomainApplicationIdentity != null )
                {
                    foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                    {
                        success &= PlugFeature( monitor, _connectionManager, rSub );
                    }
                }
                else
                {
                    if( r.Configuration.IsAllowedFeature( FeatureName, isAllowed ) )
                    {
                        success &= PlugFeature( monitor, _connectionManager, r );
                    }
                }
            }
            return Task.FromResult( success );

        }

        static bool PlugFeature( IActivityMonitor monitor, ConnectionManager remoteListeners, IRemoteParty r )
        {
            // Skip "Undefined" but this is not an error.
            if( r.DomainName == CoreApplicationIdentity.DefaultDomainName )
            {
                if( !ResolveAdresses( monitor, r, out IPEndPoint? listenIP, out IPEndPoint? targetIP ) )
                {
                    return false;
                }
                if( listenIP != null && !remoteListeners.RegisterTcpListenerParty( monitor, listenIP, r ) )
                {
                    return false;
                }
                r.AddFeature( new RemotePocoChannel( r, listenIP, targetIP ) );
            }
            return true;

            static bool ResolveAdresses( IActivityMonitor monitor, IRemoteParty r, out IPEndPoint? listenIP, out IPEndPoint? targetIP )
            {
                listenIP = null;
                targetIP = null;
                var a = r.Address;
                if( a != null )
                {
                    if( IPEndPoint.TryParse( a, out targetIP ) )
                    {
                        if( targetIP.Port == 0 ) targetIP.Port = 3712;
                        monitor.Info( $"Remote '{r.FullName}' targets '{targetIP}' address." );
                    }
                    else
                    {
                        monitor.Error( $"Invalid 'Address' for '{r.FullName}'. It must be an IPAddress with an optional port (defaults to 3712)." );
                    }
                }
                else
                {
                    var lIP = r.Configuration.Configuration.TryLookupValue( "ListeningAddress" );
                    if( lIP != null )
                    {
                        if( IPEndPoint.TryParse( lIP, out listenIP ) )
                        {
                            if( listenIP.Port == 0 ) listenIP.Port = 3712;
                            monitor.Info( $"Remote '{r.FullName}' listens on '{listenIP}' local address." );
                        }
                        else
                        {
                            monitor.Error( $"Invalid 'ListeningAddress' for '{r.FullName}'. It must be an IPAddress with an optional port (defaults to 3712)." );
                        }
                    }
                    else
                    {
                        monitor.Info( $"No 'ListeningAddress' found for '{r.FullName}'. Will listen on any interface on port 3712." );
                        listenIP = new IPEndPoint( IPAddress.Any, 3712 );
                    }
                }
                return listenIP != null || targetIP != null;
            }
        }
    }
}
