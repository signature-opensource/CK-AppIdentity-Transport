using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections;
using System.Diagnostics;
using System.Net;
using System.Threading;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class TransportFeature
    {
        readonly TransportManager _transportManager;
        readonly IRemoteParty _remote;
        readonly TransportListener? _listener;
        readonly PerfectEventSender<TransportFeature> _connectionAvailabilityChanged;
        // Channels are ordered like bestRegisteredProtocols.
        readonly List<ChannelFeature> _channels;
        // All available protocols with their versions.
        readonly HashSet<MessageProtocol> _registeredProtocols;
        // Available protocols with the highest version.
        readonly List<MessageProtocol> _bestRegisteredProtocols;

        InitialMessage? _outgoingInitialMessage;

        TransportController? _controller;
        TaskCompletionSource _readyTask;
        ConnectionAvailabitity _connectionAvailabitity;
        bool _disallowEviction;

        internal TransportFeature( TransportManager transportManager, IRemoteParty remote, TransportListener? listener, bool disallowEviction )
        {
            _transportManager = transportManager;
            _remote = remote;
            _listener = listener;
            _channels = new List<ChannelFeature>( MessageProtocolMap.MaxCount );
            _connectionAvailabilityChanged = new PerfectEventSender<TransportFeature>();
            _registeredProtocols = new HashSet<MessageProtocol>();
            _bestRegisteredProtocols = new List<MessageProtocol>( MessageProtocolMap.MaxCount );
            _readyTask = new TaskCompletionSource();
            _disallowEviction = disallowEviction;
        }

        internal async Task OnTransportAppearAsync( IActivityMonitor monitor, Transport transport, MessageProtocolMap protocols )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ), "Called from the TransportManager loop." );
            Debug.Assert( protocols.Protocols.Count == _bestRegisteredProtocols.Count );
            Debug.Assert( protocols.Protocols.Select( p => p.Name ).SequenceEqual( _bestRegisteredProtocols.Select( p => p.Name ), StringComparer.OrdinalIgnoreCase ) );

            // First, instantiates or rebinds the TransportController so that it can be
            // provided to the protocol handlers.
            if( _controller == null )
            {
                monitor.Trace( $"Creating TransportController for '{_remote.FullName}'." );
                _controller = new TransportController( _transportManager, this, transport );
            }
            else
            {
                monitor.Trace( $"Rebinding TransportController for '{_remote.FullName}'." );
                _controller.Rebind( monitor, transport );
            }
            Debug.Assert( _controller.Feature == this );
            // Second, ensures that protocol handlers for the right version are available
            // and are set to be the current one.
            var protocolHandlers = new PeerProtocolHandler[_bestRegisteredProtocols.Count];
            for( int i = 0; i < protocolHandlers.Length; i++ )
            {
                var c = _channels[i];
                Debug.Assert( c != null );
                protocolHandlers[i] = c.EnsureCurrentHandler( monitor, _controller, protocols.Protocols[i] );
            }
            // The protocols are available.
            // We start receiving messages from this new transport (this sets the protocol map and handlers on the transport)
            // and starts sending the messages in the controller queue.
            await _controller.ActivateAsync( monitor, protocols, protocolHandlers );
            // Always signals the ready task.
            _readyTask.TrySetResult();
            await UpdateConnectionAvailabitityAsync( monitor );
        }

        Task UpdateConnectionAvailabitityAsync( IActivityMonitor monitor )
        {
            Debug.Assert( _readyTask.Task.IsCompleted );

            // TODO: Consider _controller queue load.
            var a = ConnectionAvailabitity.Connected;

            if( _connectionAvailabitity != a )
            {
                _connectionAvailabitity = a;
                return _connectionAvailabilityChanged.SafeRaiseAsync( monitor, this );
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Gets the last received time (<see cref="DateTimeKind.Utc"/>).
        /// </summary>
        public DateTime LastReceived => _controller != null ? _controller.CurrentTransport.LastReceived : Util.UtcMinValue;

        /// <summary>
        /// Gets the current connection availability.
        /// </summary>
        public ConnectionAvailabitity ConnectionAvailabitity => _connectionAvailabitity;

        /// <summary>
        /// Raised whenever this <see cref="ConnectionAvailabitity"/> changed.
        /// </summary>
        public PerfectEvent<TransportFeature> ConnectionAvailabitityChanged => _connectionAvailabilityChanged.PerfectEvent;


        /// <summary>
        /// Gets the registered protocols with their best respective version among the
        /// available <see cref="RegisteredProtocols"/>.
        /// </summary>
        public IReadOnlyList<MessageProtocol> BestRegisteredProtocols
        {
            get
            {
                Debug.Assert( _bestRegisteredProtocols != null, "This is safe: see CloseChannelRegistration comment." );
                return _bestRegisteredProtocols!;
            }
        }

        /// <summary>
        /// Gets the registered protocols.
        /// </summary>
        public IReadOnlySet<MessageProtocol> RegisteredProtocols
        {
            get
            {
                Debug.Assert( _bestRegisteredProtocols != null, "This is safe: see CloseChannelRegistration comment." );
                return _registeredProtocols;
            }
        }

        internal bool RegisterChannel( IActivityMonitor monitor,
                                       ChannelFeature channel,
                                       string channelFeatureName,
                                       string protocolName,
                                       IEnumerable<ushort> protocolVersions )
        {
            Debug.Assert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            if( _bestRegisteredProtocols.Count == MessageProtocolMap.MaxCount )
            {
                monitor.Error( $"Unable to register '{channelFeatureName}'. There is already {MessageProtocolMap.MaxCount} channels registered for remote '{_remote.FullName}'." );
                return false;
            }
            int idxSorted;
            using var versions = protocolVersions.OrderByDescending( Util.FuncIdentity ).GetEnumerator();
            if( versions.MoveNext() )
            {
                idxSorted = RegisterBestProtocol( monitor, channelFeatureName, protocolName, versions.Current );
                if( idxSorted < 0 ) return false;
                while( versions.MoveNext() )
                {
                    if( !_transportManager.MessageProtocolDirectory.TryRegister( monitor, protocolName, versions.Current, out var messageProtocol ) )
                    {
                        return false;
                    }
                    if( !_registeredProtocols.Add( messageProtocol ) )
                    {
                        monitor.Error( $"Channel '{channelFeatureName}': duplicate protocol versions detected ({messageProtocol.FullName})." );
                        return false;
                    }
                }
            }
            else
            {
                idxSorted = RegisterBestProtocol( monitor, channelFeatureName, protocolName, 0 );
                if( idxSorted < 0 ) return false;
            }
            channel._baseProtocolName = protocolName;
            _channels.Insert( idxSorted, channel );
            return true;
        }

        int RegisterBestProtocol( IActivityMonitor monitor, string channelFeatureName, string protocolName, ushort version )
        {
            if( _transportManager.MessageProtocolDirectory.TryRegister( monitor, protocolName, version, out var messageProtocol ) )
            {
                int i = 0;
                for( ; i < _bestRegisteredProtocols.Count; i++ )
                {
                    int cmp = StringComparer.OrdinalIgnoreCase.Compare( messageProtocol.Name, _bestRegisteredProtocols[i].Name );
                    if( cmp == 0 )
                    {
                        monitor.Error( $"Channel '{channelFeatureName}' for remote '{_remote.FullName}': protocol '{messageProtocol.FullName}' is already managed by another channel." );
                        return -1;
                    }
                    if( cmp > 0 ) break;
                }
                _bestRegisteredProtocols.Insert( i, messageProtocol );
                _registeredProtocols.Add( messageProtocol );
                return i;
            }
            return -1;
        }

        /// <summary>
        /// The _registeredProtocols, _bestRegisteredProtocols and _channels are updated
        /// during the initialization activity.
        /// Once done, the _registeredProtocols is used to initiate outgoing connections
        /// and _bestRegisteredProtocols is used to answer to incoming connections from
        /// the listener party.
        /// No one can see this feature from other activity than the initialization one
        /// since the party and its features are not published until the initialization
        /// activity fully succeeds: it is safe to expose both _registeredProtocols and
        /// _bestRegisteredProtocols.
        /// </summary>
        internal void CloseChannelRegistration( IActivityMonitor monitor )
        {
            Debug.Assert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            Debug.Assert( _channels.Take( _bestRegisteredProtocols.Count ).All( c => c != null ) );
            Debug.Assert( _channels.Skip( _bestRegisteredProtocols.Count ).All( c => c == null ) );
            if( _bestRegisteredProtocols.Count == 0 )
            {
                monitor.Warn( $"No message protocol registered for '{_remote.FullName}'. You may want to disallow the \"TransportLayer\" feature." );
            }
            else
            {
                for( int i = 0; i < _channels.Count; ++i )
                {
                    _channels[i]._protocolNumber = i + 1;
                }
            }
        }

        /// <summary>
        /// Gets a task that is completed when a connection has been established or re-established.
        /// </summary>
        public Task ReadyTask => _readyTask.Task;

        /// <summary>
        /// Gets the party.
        /// </summary>
        public IRemoteParty Party => _remote;

        /// <summary>
        /// Gets whether we are listening or calling the remote.
        /// </summary>
        public bool IsListening => _listener != null;

        /// <summary>
        /// Gets or sets whether this remote disallows a new remote incoming transport
        /// when a remote instance is currently connected. This applies only if <see cref="IsListening"/> is true.
        /// Defaults to false: a new remote connection replaces the current one.
        /// </summary>
        public bool DisallowEviction
        {
            get => _disallowEviction;
            set => _disallowEviction = value;
        }

        /// <summary>
        /// Gets the initial message to send when this is a caller.
        /// This will be used each time a new connection must be established.
        /// </summary>
        internal InitialMessage? OutgoingInitialMessage => _outgoingInitialMessage;

        internal void InitializeOutgoing( TransportTypeAddress target )
        {
            _outgoingInitialMessage = new InitialMessage( this );
            _transportManager.TryConnectTo( this, target );
        }

        internal TransportController? TransportController => _controller;

        /// <summary>
        /// We don't want to expose any DisposeAsync or Dispose on this public TransportFeature.
        /// This is called when tearing down the remote party.
        /// </summary>
        internal ValueTask TeardownAsync( IActivityMonitor monitor )
        {
            // If we are not connected:
            //   - If the party is a caller, we don't have anything to do: the OutgoingConnectionBackTask
            //     tests the party.IsDestroyed and dies.
            //   - If we are listening we must remove this party from the listener.
            _listener?.RemoveParty( this );
            // Closing the transport is done from the transport manager loop.
            var e = _controller;
            if( e != null )
            {
                return e.TeardownAsync( monitor );
            }
            return default;
        }

    }

}
