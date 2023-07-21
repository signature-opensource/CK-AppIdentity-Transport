using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Drives the <see cref="TransportFeature"/> remote's and <see cref="TransportManagerFeature"/> lifetime.
    /// The <see cref="TransportManagerFeature"/> is added to the <see cref="ApplicationIdentityService"/>'s features.
    /// </summary>
    public class TransportFeatureDriver : ApplicationIdentityFeatureDriver
    {
        readonly TransportTypeService[] _transportTypes;
        readonly TcpSocketTransportTypeService _tcp;
        readonly MessageProtocolDirectoryService _protocolDirectory;
        TransportManager? _transportManager;

        /// <summary>
        /// Initializes a new transport driver.
        /// </summary>
        /// <param name="s">The application identity service.</param>
        /// <param name="transportTypes">The available type of transports.</param>
        /// <param name="protocolDirectory">The transport protocol directory.</param>
        public TransportFeatureDriver( ApplicationIdentityService s,
                                       IEnumerable<ITransportTypeService> transportTypes,
                                       MessageProtocolDirectoryService protocolDirectory )
            : base( s, isAllowedByDefault: true )
        {
            _transportTypes = transportTypes.Cast<TransportTypeService>().ToArray();
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
            // Even if initialization fails, register the feature: it may be required by others.
            ApplicationIdentityService.AddFeature( _transportManager.Feature );
            // Local and External remote parties have no Transport.
            foreach( var r in context.GetAllRemotes().Where( r => !r.IsExternalParty && IsAllowedFeature( r ) ) )
            {
                success &= PlugTransportFeature( context, r );
            }
            return Task.FromResult( success );
        }

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty remote )
        {
            bool success = true;
            // Local and External remote parties have no Transport.
            foreach( var r in context.GetAllRemotes().Where( r => !r.IsExternalParty && IsAllowedFeature( r ) ) )
            {
                success &= PlugTransportFeature( context, r );
            }
            return Task.FromResult( success );
        }

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty remote )
        {
            Debug.Assert( _transportManager != null );
            foreach( var r in context.GetAllRemotes() )
            {
                var t = r.GetFeature<TransportFeature>();
                if( t != null ) _transportManager.TearDown( t );
            }
            return Task.CompletedTask;
        }

        protected override Task TeardownAsync( FeatureLifetimeContext context )
        {
            Debug.Assert( _transportManager != null );
            foreach( var r in context.GetAllRemotes() )
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
            // If we cannot resolve the listening addresses or the target address, it's an error.
            if( !ResolveAdresses( context.Monitor, r, out IReadOnlyCollection<TransportTypeAddress>? listen, out TransportTypeAddress? target ) )
            {
                return false;
            }
            Debug.Assert( (listen == null) != (target == null) );
            // Transport requires the KeyManagement feature:
            // - If we are listening, then we must have a IRemoteKeys manager to assert the incoming message update
            //   the trusted identity and then the ILocalKeys to sign the response.
            // - If we are targeting, then we must have a ILocalKeys manager to sign the initial message and then
            //   the IRemoteKeys to assert the response and update the trusted identity.
            IRemoteKeys? remoteKeys = r.GetFeature<IRemoteKeys>(); ;
            if( remoteKeys == null )
            {
                context.Monitor.Warn( $"Remote '{r}' cannot support the allowed 'Transport' feature because the remote has a disallowed 'KeyManagement' feature." );
                // This is not an error.
                return true;
            }
            // If we are listening and cannot setup the listeners on the local address, it's an error.
            TransportListener[]? listeners = null;
            bool disallowEviction = false;
            if( listen != null )
            {
                listeners = new TransportListener[listen.Count];
                int i = 0;
                foreach( var l in listen )
                {
                    var listener = _transportManager.TryEnsureListener( context.Monitor, l );
                    if( listener == null )
                    {
                        return false;
                    }
                    listeners[i++] = listener;
                }
                var a = r.Configuration.Configuration.TryLookupValue( "DisallowEviction" );
                disallowEviction = bool.TryParse( a, out var b ) && b;
            }
            // No direct initialization error: add the TransportFeature to the party.
            // The initialization is not finished: if the party is listening it must be registered in its
            // listener and if the party is the initiator it must start to try to connect.
            // However, to be able to start exchanging with others, we must know the message protocols
            // that are supported.
            var t = new TransportFeature( _transportManager, r, listeners, target, remoteKeys, disallowEviction );
            // We add the feature here to the remote so that channels can use it.
            // And we wait a successful initialization to "publish" the new TransportFeature to the
            // public TransportManagerFeature during the second round of OnSuccess so that the TransportFeature
            // "appears" after the ApplicationIdentity.RemotesChanged event.
            r.AddFeature( t );
            if( listeners != null )
            {
                context.Trampoline.OnSuccess( () =>
                {
                    t.CloseChannelRegistration( context.Monitor );
                    foreach( var l in listeners ) l.AddParty( t );
                    context.Trampoline.OnSuccess( () => _transportManager.RaiseFeatureAppearsEventAsync( context.Monitor, t ) );
                } );
            }
            else
            {
                Debug.Assert( target != null );
                context.Trampoline.OnSuccess( () =>
                {
                    t.CloseChannelRegistration( context.Monitor );
                    t.InitializeOutgoingAndInitiateConnection();
                    context.Trampoline.OnSuccess( () => _transportManager.RaiseFeatureAppearsEventAsync( context.Monitor, t ) );
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
                    if( p.Equals( t.TypeName, StringComparison.OrdinalIgnoreCase) )
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

        bool ResolveAdresses( IActivityMonitor monitor,
                              IRemoteParty r,
                              out IReadOnlyCollection<TransportTypeAddress>? listen,
                              out TransportTypeAddress? target )
        {
            // If the Address is set, it must be parseable.
            var a = r.Address;
            if( a != null )
            {
                var section = r.Configuration.Configuration.TryGetSection( "Address" );
                Debug.Assert( section != null );
                listen = null;
                target = ParseTypedAddress( monitor, a, section );
                return target != null;
            }
            // No Address: lookup for the ListeningAddress.
            // ReadListeningAddresses returns true if no error occurred but the address map can be null.
            target = null;
            listen = ResolveListeningAddresses( monitor, r );
            return listen != null;
        }

        IReadOnlyCollection<TransportTypeAddress>? ResolveListeningAddresses( IActivityMonitor monitor, IParty party )
        {
            if( !ReadListeningAddresses( monitor, party.Configuration.Configuration, out var available ) )
            {
                return null;
            }
            Debug.Assert( available == null || available.Count > 0, "If there is a map, it is not empty." );
            // If there is a single listening address, we are done: there is no ambiguity.
            if( available != null && available.Count == 1 )
            {
                return available.Values;
            }
            // If there is no "ListeningAddress" at all, consider the default tcp listening address
            // bound to the root ApplicationIdentityService configuration.
            var rootConfiguration = party.ApplicationIdentityService.Configuration.Configuration;
            if( available == null )
            {
                var tcpDef = _tcp.DefaultListeningAddress;
                Debug.Assert( tcpDef != null );
                return new[] { new TransportTypeAddress( _tcp, rootConfiguration, tcpDef ) };
            }
            // If there is more than one type of Transport, inject the defaults of all transport type (if supported and
            // if no address exist for them) and let "ListeningTypes" decides or use the 'all' if "ListeningTypes" is missing.
            foreach( var t in _transportTypes )
            {
                if( !available.ContainsKey( t ) )
                {
                    var def = t.DefaultListeningAddress;
                    if( def != null )
                    {
                        available.Add( t, new TransportTypeAddress( t, rootConfiguration, def ) );
                    }
                }
            }
            var listeningTypesSection = party.Configuration.Configuration.TryLookupSection( "ListeningTypes" );
            if( listeningTypesSection == null )
            {
                monitor.Warn( $"No \"ListeningTypes\" configuration for Party '{party.FullName}'. " +
                              $"Using all available ListeningAddress: {available.Values.Select( a => a.ToString() ).Concatenate()}." );
                return available.Values;
            }
            var listeningTypeNames = listeningTypesSection.ReadUniqueStringSet( monitor, StringComparer.OrdinalIgnoreCase );
            if( listeningTypeNames == null ) return null;
            if( listeningTypeNames.Count == 0 )
            {
                monitor.Error( $"Invalid '{listeningTypesSection.Path}' empty configuration for Party '{party.FullName}'. " +
                               $"At least one of '{_transportTypes.Select( t => t.TypeName ).Concatenate("','")}' or 'all' must be specified.'" );
                return null;
            }
            // Detecting invalid or unavailable type names and the 'all' occurrence,
            // or builds the set of final TransportTypeAddress.
            List<TransportTypeAddress>? final = null;
            foreach( var t in listeningTypeNames )
            {
                if( t.Equals( "all", StringComparison.OrdinalIgnoreCase ) )
                {
                    return available.Values;
                }
                var exist = available.Values.FirstOrDefault( exist => exist.Type.TypeName.Equals( t, StringComparison.OrdinalIgnoreCase ) );
                if( exist == null )
                {
                    monitor.Error( $"Invalid value '{t}' in '{listeningTypesSection.Path}' for Party '{party.FullName}'.{Environment.NewLine}" +
                                   $"Available transport types here are: '{available.Values.Select( t => t.Type.TypeName ).Concatenate( "','" )}'." );
                    return null;
                }
                final ??= new List<TransportTypeAddress>();
                final.Add( exist );
            }
            return final;
        }

        bool ReadListeningAddresses( IActivityMonitor monitor,
                                     ImmutableConfigurationSection configuration,
                                     out Dictionary<ITransportTypeService, TransportTypeAddress>? result )
        {
            result = null;
            List<ITransportTypeService>? locally = null;
            foreach( var config in configuration.LookupAllSection( "ListeningAddress" ) )
            {
                var onLevel = config.ReadStringArray( monitor );
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
                            monitor.Error( $"Invalid '{configuration.Path}': more than one address for '{parsed.Type.TypeName}' transport type." );
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
