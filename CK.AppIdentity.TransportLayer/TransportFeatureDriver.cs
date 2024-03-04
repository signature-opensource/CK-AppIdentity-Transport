using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Drives the <see cref="TransportFeature"/> remote's and <see cref="TransportManagerFeature"/> lifetime.
    /// The <see cref="TransportManagerFeature"/> is added to the <see cref="ApplicationIdentityService"/>'s features.
    /// </summary>
    public partial class TransportFeatureDriver : ApplicationIdentityFeatureDriver
    {
        readonly TransportTypeService[] _transportTypes;
        readonly TcpSocketTransportTypeService _tcp;
        readonly MessageProtocolDirectoryService _protocolDirectory;
        TransportManager? _transportManager;

        /// <summary>
        /// Initializes a new transport driver.
        /// </summary>
        /// <param name="s">The application identity service.</param>
        /// <param name="keyManagement">The Key management is required: the RemoteKeys must be initialized before the TransportFeatures.</param>
        /// <param name="transportTypes">The available type of transports.</param>
        /// <param name="protocolDirectory">The transport protocol directory.</param>
        public TransportFeatureDriver( ApplicationIdentityService s,
                                       KeyManagementFeatureDriver keyManagement,
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
            // Locals hold the Listeners.
            // Starts by creating the remotes.
            var releaseOnError = new List<TransportListener>();
            context.Trampoline.OnError( () => ReleaseListenersAsync( context.Monitor, releaseOnError ) );
            foreach( var r in context.GetAllRemotes().Where( r => !r.IsExternalParty && IsAllowedFeature( r ) ) )
            {
                success &= PlugTransportFeature( context, r, releaseOnError.Add );
            }
            foreach( var local in ApplicationIdentityService.TenantDomains.Cast<ILocalParty>().Prepend( ApplicationIdentityService ) )
            {
                success &= EnsureAlwaysListeningListeners( context, local, releaseOnError.Add );
            }
            return Task.FromResult( success );
        }

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
        {
            bool success = true;
            var releaseOnError = new List<TransportListener>();
            context.Trampoline.OnError( () => ReleaseListenersAsync( context.Monitor, releaseOnError ) );
            // Local and External remote parties have no Transport.
            foreach( var r in context.GetAllRemotes().Where( r => !r.IsExternalParty && IsAllowedFeature( r ) ) )
            {
                success &= PlugTransportFeature( context, r, releaseOnError.Add );
            }
            if( party is ILocalParty local )
            {
                success &= EnsureAlwaysListeningListeners( context, local, releaseOnError.Add );
            }
            return Task.FromResult( success );
        }

        protected override async Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
        {
            Throw.DebugAssert( _transportManager != null );
            foreach( var r in context.GetAllRemotes() )
            {
                var t = r.GetFeature<TransportFeature>();
                if( t != null )
                {
                    await UnplugRemoteAsync( context, t, shutdown: false );
                }
            }
            // Handles the potential "AlwaysListening" on the local.
            if( party is ILocalParty local )
            {
                var listeners = local.GetFeature<TransportListener[]>();
                if( listeners != null ) await ReleaseListenersAsync( context.Monitor, listeners );
            }
        }

        protected override async Task TeardownAsync( FeatureLifetimeContext context )
        {
            Throw.DebugAssert( _transportManager != null );
            foreach( var r in context.GetAllRemotes() )
            {
                var t = r.GetFeature<TransportFeature>();
                if( t != null )
                {
                    await UnplugRemoteAsync( context, t, shutdown: true );
                }
            }
            // Handles the potential "AlwaysListening" on the local.
            foreach( var local in ApplicationIdentityService.TenantDomains.Cast<ILocalParty>().Prepend( ApplicationIdentityService ) )
            {
                var listeners = local.GetFeature<TransportListener[]>();
                if( listeners != null ) await ReleaseListenersAsync( context.Monitor, listeners );
            }
            // Sends the stop signal and wait for the resolution of the running task
            // before returning to the ApplicationIdentity service's agent activity. 
            _transportManager.Stop();
            await _transportManager.RunningTask;
        }

        static async Task<bool> ReleaseListenersAsync( IActivityMonitor monitor, IEnumerable<TransportListener> toRelease )
        {
            foreach( var l in toRelease )
            {
                await l.ReleaseAsync( monitor );
            }
            return false;
        }

        async Task UnplugRemoteAsync( FeatureLifetimeContext context, TransportFeature t, bool shutdown )
        {
            Throw.DebugAssert( _transportManager != null );
            if( t.IsListening )
            {
                // Removes the party from the listeners (if we were listening).
                foreach( var l in t.Listeners ) l.RemoveParty( context.Monitor, t );
            }
            // This calls the TransportFeature.DoSwitchOffAsync with "ApplicationIdentityShutdown" or "PartyDestroyed"
            // and awaits the operation: both AppIdentity and TransportManager agents are waiting. 
            await _transportManager.TearDownAsync( t, serviceShutdown: shutdown );
            // Release the listeners from the ApplicationIdentityService's agent loop.
            if( t.IsListening )
            {
                await ReleaseListenersAsync( context.Monitor, t.Listeners );
            }
        }

        bool EnsureAlwaysListeningListeners( FeatureLifetimeContext context, ILocalParty local, Action<TransportListener> releaseOnError )
        {
            Throw.DebugAssert( _transportManager != null );
            // If AlwaysListening is false (the default), Listeners are created when the first non initiator
            // remote (no Address) appears.
            // We initialize the Listeners only if "AlwaysListening" is true.
            if( !local.Configuration.Configuration.LookupBooleanValue( context.Monitor, "AlwaysListening" ) )
            {
                return true;
            }
            var listen = ResolveListeningAddresses( context.Monitor, local );
            if( listen == null ) return false;
            TransportListener[]? listeners = ObtainListeners( context, listen, releaseOnError );
            if( listeners == null ) return false;
            // The existence of the TransportListener[] feature on the local is the marker
            // of the "AlwaysListening": this has incremented the reference counter of all listeners
            // for this local.
            local.AddFeature( listeners );
            return true;
        }

        bool PlugTransportFeature( FeatureLifetimeContext context, IRemoteParty r, Action<TransportListener> releaseOnError )
        {
            Throw.DebugAssert( _transportManager != null );
            Throw.DebugAssert( r.DomainName != CoreApplicationIdentity.DefaultDomainName && !r.IsExternalParty );
            // If we cannot resolve the listening addresses or the target address, it's an error.
            if( !ResolveAdresses( context.Monitor, r, out IReadOnlyCollection<TransportTypeAddress>? listen, out TransportTypeAddress? target ) )
            {
                return false;
            }
            Throw.DebugAssert( (listen == null) != (target == null) );
            // Transport requires the KeyManagement feature:
            // - If we are listening, then we must have a IRemoteKeys manager to assert the incoming message update
            //   the trusted identity and then the ILocalKeys to sign the response.
            // - If we are targeting, then we must have a ILocalKeys manager to sign the initial message and then
            //   the IRemoteKeys to assert the response and update the trusted identity.
            IRemoteKeys? remoteKeys = r.GetFeature<IRemoteKeys>();
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
                listeners = ObtainListeners( context, listen, releaseOnError );
                if( listeners == null ) return false;
                disallowEviction = r.Configuration.Configuration.LookupBooleanValue( context.Monitor, nameof( TransportFeature.DisallowEviction ) );
            }
            // No direct initialization error: add the TransportFeature to the party.
            // The initialization is not finished: if the party is listening it must be registered in its
            // listeners and if the party is the initiator it must start to try to connect.
            // Before being able to start exchanging with others, we must know the message protocols
            // that are supported: CloseChannelRegistration does this.
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
                    foreach( var l in listeners ) l.AddParty( context.Monitor, t );
                    context.Trampoline.OnSuccess( () => _transportManager.RaiseFeatureAppearsEventAsync( context.Monitor, t ) );
                } );
            }
            else
            {
                Throw.DebugAssert( target != null );
                context.Trampoline.OnSuccess( () =>
                {
                    t.CloseChannelRegistration( context.Monitor );
                    t.InitializeOutgoingAndInitiateConnection();
                    context.Trampoline.OnSuccess( () => _transportManager.RaiseFeatureAppearsEventAsync( context.Monitor, t ) );
                } );
            }
            return true;
        }

        TransportListener[]? ObtainListeners( FeatureLifetimeContext context,
                                              IReadOnlyCollection<TransportTypeAddress> listen,
                                              Action<TransportListener> releaseOnError )
        {
            Throw.DebugAssert( _transportManager != null );
            TransportListener[]? listeners = new TransportListener[listen.Count];
            int i = 0;
            foreach( var addr in listen )
            {
                var listener = _transportManager.TryEnsureListener( context.Monitor, addr );
                if( listener == null ) break;
                listeners[i++] = listener;
                // Registers the newly created to be released on error. 
                releaseOnError( listener );
            }
            return i < listeners.Length ? null : listeners;
        }
    }
}
