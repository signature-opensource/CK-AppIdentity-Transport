using CK.Core;
using System.Diagnostics;
using System.IO;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Drives the <see cref="TransportFeature"/> remote's lifetime.
    /// The <see cref="TransportManager"/> is added in the <see cref="ApplicationIdentityService"/>'s features.
    /// </summary>
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
            // Domains named "Undefined" have no Transport.
            foreach( var r in context.GetAllLeafRemotes()
                                     .Where( r => r.DomainName != CoreApplicationIdentity.DefaultDomainName && IsAllowedFeature( r ) ) )
            {
                success &= PlugTransportFeature( context, r );
            }
            return Task.FromResult( true );
        }

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty remoteParty )
        {
            bool success = true;
            // Domains named "Undefined" have no Transport.
            foreach( var r in context.GetAllLeafRemotes()
                                     .Where( r => r.DomainName != CoreApplicationIdentity.DefaultDomainName && IsAllowedFeature( r ) ) )
            {
                success &= PlugTransportFeature( context, r );
            }
            return Task.FromResult( success );
        }

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty party )
        {
            Debug.Assert( _transportManager != null );
            foreach( var r in context.GetAllLeafRemotes() )
            {
                var t = r.GetFeature<TransportFeature>();
                if( t != null ) _transportManager.TearDown( t );
            }
            return Task.CompletedTask;
        }

        protected override Task TeardownAsync( FeatureLifetimeContext context )
        {
            Debug.Assert( _transportManager != null );
            foreach( var r in context.GetAllLeafRemotes() )
            {
                var t = r.GetFeature<TransportFeature>();
                if( t != null ) _transportManager.TearDown( t );
            }
            // Sends the stop signal and wait for the resolution of the running task
            // before returning to the ApplicationIdentity service's agent activity. 
            _transportManager.Stop();
            return _transportManager.RunningTask;
        }

        bool PlugTransportFeature( FeatureLifetimeContext context, IRemoteParty r )
        {
            Debug.Assert( _transportManager != null );
            Debug.Assert( r.DomainName != CoreApplicationIdentity.DefaultDomainName );
            // If we cannot resolve the listening or target address, it's an error.
            if( !ResolveAdresses( context.Monitor, r, out TransportTypeAddress? listen, out TransportTypeAddress? target ) )
            {
                return false;
            }
            Debug.Assert( (listen == null) != (target == null) );
            // If we are listening and cannot setup a listener on the local address, it's an error.
            TransportListener? listener = null;
            bool disallowEviction = false;
            if( listen != null )
            {
                if( (listener = _transportManager.TryEnsureListener( context.Monitor, listen )) == null )
                {
                    return false;
                }
                var a = r.Configuration.Configuration.TryLookupValue( "DisallowEviction" );
                disallowEviction = a != null && a.Equals( "True", StringComparison.OrdinalIgnoreCase );
            }
            // No direct initialization error: add the TransportFeature to the party.
            // The initialization is not finished: if the party is listening it must be registered in its
            // listener and if the party is the initiator it must start to try to connect.
            // However, to be able to start exchanging with others, we must know the message protocols
            // that are supported.
            var t = new TransportFeature( _transportManager, r, listener, target, disallowEviction );
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
                    t.InitializeOutgoingAndInitiateConnection();
                } );
            }
            return true;
        }

        TransportTypeAddress? ParseTypedAddress( IActivityMonitor monitor, string s, ImmutableConfigurationSection section )
        {
            ITransportTypeService? transport = null;
            ReadOnlySpan<char> typed = s.AsSpan();
            int idx = s.IndexOf( ':' );
            if( idx > 0 )
            {
                var p = s.AsSpan( 0, idx );
                foreach( var t in _transportTypes )
                {
                    if( p.Equals( t.AddressProtocolName, StringComparison.OrdinalIgnoreCase) )
                    {
                        typed = s.AsSpan( idx + 1 );
                        transport = t;
                        break;
                    }
                }
                if( transport == null )
                {
                    monitor.Error( $"Transport type '{p}' not found for '{section.Path}', address: '{s}'.");
                    return null;
                }
            }
            else
            {
                transport = _tcp;
            }
            return transport.ParseAddress( monitor, typed, section );
        }

        bool ResolveAdresses( IActivityMonitor monitor, IRemoteParty r, out TransportTypeAddress? listen, out TransportTypeAddress? target )
        {
            listen = null;
            target = null;
            // If the Address is set, it must be parseable.
            var a = r.Address;
            if( a != null )
            {
                var section = r.Configuration.Configuration.TryGetSection( "Address" );
                Debug.Assert( section != null );
                target = ParseTypedAddress( monitor, a, section );
                return target != null;
            }
            // No Address: lookup for the ListeningAddress.
            // ReadListeningAddresses returns true if no error occurred but the address map can be null.
            if( !ReadListeningAddresses( monitor,r, out var available ) )
            {
                return false;
            }
            Debug.Assert( available == null || available.Count > 0, "If there is a map, it is not empty." );
            // If there is a single listening address, we are done: there is no ambiguity.
            if( available != null && available.Count == 1 )
            {
                listen = available.Values.First();
                return true;
            }
            // If there is no "ListeningAddress" at all, consider the default tcp listening address
            // bound to the ApplicationIdentity.Local configuration that can be the root or a domain.
            // Note: currently only tcp has this "DefaultListeningAddress" (other transports cannot define such
            // a default address). This may be changed in the future if needed.
            var defaultTcpListening = _tcp.GetDefaultListeningAddress( r.ApplicationIdentity.Configuration.Local.Configuration );
            if( available == null )
            {
                listen = defaultTcpListening;
                return true;
            }
            // If there is more than one type of Transport, inject the tcp default if no tcp address exists
            // and let "UseTransport" decides or use the 'tcp' if "UseTransport" is missing.
            available.TryAdd( _tcp, defaultTcpListening );
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
                        var parsed = ParseTypedAddress( monitor, raw, config );
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
    }
}
