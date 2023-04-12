using CK.Core;
using System.Diagnostics;
using System.IO;

namespace CK.AppIdentity.TransportLayer
{

    public class TransportFeatureDriver : ApplicationIdentityFeatureDriver
    {
        readonly ITransportTypeService[] _transportTypes;
        readonly TcpSocketTransportTypeService _tcp;
        readonly MessageProtocolDirectoryService _protocolDirectory;
        TransportManager? _transportManager;

        public TransportFeatureDriver( ApplicationIdentityService s, IEnumerable<ITransportTypeService> transportTypes, MessageProtocolDirectoryService protocolDirectory )
            : base( s, isAllowedByDefault: true )
        {
            _transportTypes = transportTypes.ToArray();
            _tcp = _transportTypes.OfType<TcpSocketTransportTypeService>().Single();
            _protocolDirectory = protocolDirectory;
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
        {
            _transportManager = new TransportManager( context.Agent, _protocolDirectory );
            bool success = _transportManager.Start();
            if( !success )
            {
                context.Monitor.Error( "Unable to start the Transport Manager." );
            }
            // Even if initialization fails, register the features: it may be required by others.
            ApplicationIdentityService.AddFeature( _transportManager );
            foreach( var r in ApplicationIdentityService.Remotes )
            {
                success &= SetupDynamicRemote( context, r );
            }
            return Task.FromResult( true );
        }

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty remoteParty )
        {
            return Task.FromResult( SetupDynamicRemote( context, remoteParty ) );
        }

        bool SetupDynamicRemote( FeatureLifetimeContext context, IRemoteParty r )
        {
            bool success = true;
            if( r.DomainApplicationIdentity != null )
            {
                foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                {
                    if( IsAllowedFeature( rSub ) )
                    {
                        success &= PlugTransportFeature( context, rSub );
                    }
                }
            }
            else if( IsAllowedFeature( r ) )
            {
                success &= PlugTransportFeature( context, r );
            }
            return success;
        }

        bool PlugTransportFeature( FeatureLifetimeContext context, IRemoteParty r )
        {
            Debug.Assert( _transportManager != null );
            // Skip "Undefined" but this is not an error.
            if( r.DomainName != CoreApplicationIdentity.DefaultDomainName )
            {
                // If we cannot resolve the listening or target address, it's an error.
                if( !ResolveAdresses( context.Monitor, r, out TransportTypeAddress? listen, out TransportTypeAddress? target ) )
                {
                    return false;
                }
                Debug.Assert( (listen == null) != (target == null) );
                // If we are listening and cannot setup a listener on the local address, it's an error.
                TransportListener? listener = null;
                if( listen != null )
                {
                    if( (listener = listen.Type.TryEnsureListener( context.Monitor, _transportManager, listen )) == null )
                    {
                        return false;
                    }
                }
                // No direct initialization error: add the TransportFeature to the party.
                // The initialization is not finished: if the party is listening it must be registered in its
                // listener and if the party is the initiator it must start to try to connect.
                // However, to be able to start exchanging with others, we must know the message protocols
                // that are supported.
                var t = new TransportFeature( _transportManager, r, listener );
                r.AddFeature( t );
                if( listener != null )
                {
                    context.Trampoline.OnSuccess( () =>
                    {
                        t.CloseChannelRegistration( context.Monitor );
                        listener.AddParty( t );
                    } );
                }
                else
                {
                    Debug.Assert( target != null );
                    context.Trampoline.OnSuccess( () =>
                    {
                        t.CloseChannelRegistration( context.Monitor );
                        t.InitializeOutgoing( target );
                    } );
                }
            }
            return true;
        }

        TransportTypeAddress? ParseTypedAddress( IActivityMonitor monitor, string s, string configurationPath, string? configurationKey )
        {
            ITransportTypeService? transport = null;
            ReadOnlySpan<char> typed = s.AsSpan();
            int idx = s.IndexOf( ':' );
            if( idx > 0 )
            {
                var p = s.AsSpan( 0, idx );
                foreach( var t in _transportTypes )
                {
                    if( p.Equals(t.AddressProtocolName, StringComparison.OrdinalIgnoreCase) )
                    {
                        typed = s.AsSpan( idx + 1 );
                        transport = t;
                        break;
                    }
                }
                if( transport == null )
                {
                    monitor.Error( $"Transport type '{p}' not found for '{string.Join( ':', configurationPath, configurationKey )}', address: '{s}'.");
                    return null;
                }
            }
            else
            {
                transport = _tcp;
            }
            return transport.ParseAddress( monitor, typed, configurationPath, configurationKey );
        }

        bool ResolveAdresses( IActivityMonitor monitor, IRemoteParty r, out TransportTypeAddress? listen, out TransportTypeAddress? target )
        {
            listen = null;
            target = null;
            var a = r.Address;
            if( a != null )
            {
                target = ParseTypedAddress( monitor, a, r.Configuration.Configuration.Path, "Address" );
                return target != null;
            }
            if( !ReadListeningAddresses(monitor,r, out var available ) )
            {
                return false;
            }
            if( available == null )
            {
                listen = _tcp.DefaultListeningAddress;
                return true;
            }
            available.TryAdd( _tcp, _tcp.DefaultListeningAddress );
            Debug.Assert( available.Count >= 2 );
            var useTransportSection = r.Configuration.Configuration.TryLookupSection( "UseTransport" );
            var useTransport = useTransportSection?.Value;
            if( useTransport == null )
            {
                monitor.Warn( $"Missing a \"UseTransport\" configuration for Remote '{r.FullName}'. Using the default 'tcp' transport type." );
                listen = available[_tcp];
                return true;
            }
            foreach( var listeningAddress in available.Values )
            {
                if( useTransport.Equals( listeningAddress.Type.AddressProtocolName, StringComparison.OrdinalIgnoreCase ) )
                {
                    listen = listeningAddress;
                    return true;
                }
            }
            Debug.Assert( useTransportSection != null );
            monitor.Error( $"Invalid '{useTransportSection.Path}': no ListeningAddress exist for transport type '{useTransport}'." );
            return false;
        }

        bool ReadListeningAddresses( IActivityMonitor monitor, IRemoteParty r, out Dictionary<ITransportTypeService, TransportTypeAddress>? result )
        {
            result = null;
            List<ITransportTypeService>? locally = null;
            foreach( var config in r.Configuration.Configuration.LookupAllSection( "ListeningAddress" ) )
            {
                var onLevel = ApplicationIdentityConfiguration.ReadStringArray( monitor, config );
                if( onLevel == null ) return false;
                if( onLevel.Length > 0 )
                {
                    if( locally == null ) locally = new List<ITransportTypeService>();
                    else locally.Clear();
                    foreach( var raw in onLevel )
                    {
                        var parsed = ParseTypedAddress( monitor, raw, config.Path, null );
                        if( parsed == null ) return false;
                        if( locally.Contains( parsed.Type ) )
                        {
                            monitor.Error( $"Invalid '{r.Configuration.Configuration.Path}': more than one address for '{parsed.Type.AddressProtocolName}' transport type." );
                            return false;
                        }
                        result ??= new Dictionary<ITransportTypeService, TransportTypeAddress>();
                        result[parsed.Type] = parsed;
                    }
                }
            }
            return true;
        }

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty party )
        {
            if( party.DomainName != CoreApplicationIdentity.DefaultDomainName )
            {
                if( party.DomainApplicationIdentity != null )
                {
                    foreach( var rSub in party.DomainApplicationIdentity.Remotes )
                    {
                        var t = rSub.GetFeature<TransportFeature>();
                        t?.Teardown( context.Monitor );
                    }
                }
                else 
                {
                    var t = party.GetFeature<TransportFeature>();
                    t?.Teardown( context.Monitor );
                }
            }
            return Task.CompletedTask;
        }

        protected override Task TeardownAsync( FeatureLifetimeContext context )
        {
            Debug.Assert( _transportManager != null );
            foreach( var r in ApplicationIdentityService.Remotes )
            {
                var t = r.GetFeature<TransportFeature>();
                t?.Teardown( context.Monitor );
            }
            _transportManager.SendStop();
            return _transportManager.RunningTask;
        }
    }
}
