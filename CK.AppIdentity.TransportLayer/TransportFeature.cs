using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading;

namespace CK.AppIdentity.TransportLayer
{

    /// <summary>
    /// Centralizes communication feature for a remote.
    /// This feature is available only on a <see cref="IRemoteParty"/>. 
    /// </summary>
    public sealed class TransportFeature
    {
        /// <summary>
        /// Maximal allowed clock offset between parties is 10 minutes.
        /// </summary>
        public static readonly TimeSpan MaxClockOffset = TimeSpan.FromMinutes( 10 );

        readonly TransportManager _transportManager;
        readonly IRemoteParty _party;

        // Either listener or target is not null.
        readonly TransportListener? _listener;

        readonly TransportTypeAddress? _target;

        readonly ILocalKeys _localKeys;
        readonly IRemoteKeys _remoteKeys;

        readonly PerfectEventSender<TransportFeature> _connectionAvailabilityChanged;
        // This relays our ConnectionAvailabilityChanged event to the TransportManagerFeature one.
        // We must dispose it when tearing down this feature.
        readonly IBridge _connectionEventBridge;

        // Channels are ordered like bestRegisteredProtocols.
        readonly List<ChannelFeature> _channels;
        // All available protocols with their versions.
        readonly HashSet<MessageProtocol> _registeredProtocols;
        // Available protocols with the highest version.
        readonly List<MessageProtocol> _bestRegisteredProtocols;

        InitialMessage? _outgoingInitialMessage;

        string? _switchOffReason;
        TransportController? _controller;
        TaskCompletionSource _readyTask;
        ConnectionAvailability _connectionAvailabilty;
        bool _disallowEviction;

        internal TransportFeature( TransportManager transportManager,
                                   IRemoteParty remote,
                                   TransportListener? listener,
                                   TransportTypeAddress? target,
                                   ILocalKeys localKeys,
                                   IRemoteKeys remoteKeys,
                                   bool disallowEviction )
        {
            Debug.Assert( (listener == null) != (target == null), "Either we are listening or we are targeting." );
            _transportManager = transportManager;
            _party = remote;
            _listener = listener;
            _remoteKeys = remoteKeys;
            _target = target;
            _localKeys = localKeys;
            _channels = new List<ChannelFeature>( MessageProtocolMap.MaxCount );

            _connectionAvailabilityChanged = new PerfectEventSender<TransportFeature>();
            _connectionEventBridge = _connectionAvailabilityChanged.CreateRelay( _transportManager.Feature._connectionAvailabilityChanged );

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
                monitor.Trace( $"Creating TransportController for '{_party.FullName}'." );
                _controller = new TransportController( _transportManager, this, transport );
            }
            else
            {
                monitor.Trace( $"Rebinding TransportController for '{_party.FullName}'." );
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
            // and starts sending the messages in the controller queues.
            await _controller.ActivateAsync( monitor, protocols, protocolHandlers );
            // Always signals the ready task.
            _readyTask.TrySetResult();
            await UpdateConnectionAvailabilityAsync( monitor );
        }

        Task UpdateConnectionAvailabilityAsync( IActivityMonitor monitor )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ), "Called from the TransportManager loop." );

            // TODO: Consider _controller queue load.
            // Currently we are connected if no off reason exists and a controller has been created and its lifetime has not been signaled.
            // Eviction is transparent (the previous transport ends its receive works) but errors followed by a successful reconnection can be observed.
            // But since this is currently called by OnTransportAppearAsync (reconnection case) and DoSwithOff (explicit disconnection case),
            // no intermediate state will be emitted.
            // We definitely need a more complex code with:
            //  - controller sender channel load.
            //  - disconnection time (based on LastReceived and may be a LastSent - when the remote is passive).
            // This may be coupled to the KeepAlive implementation and rely on one (or more) back tasks.
            var a = IsOff || _controller?.CurrentTransport?.Lifetime.IsCancellationRequested is true
                        ? ConnectionAvailability.None
                        : ConnectionAvailability.Connected;

            if( _connectionAvailabilty != a )
            {
                // If we are "strongly" disconnected, we tell the channels that their CurrentHandler is
                // no more available.
                if( a == ConnectionAvailability.None )
                {
                    foreach( var c in _channels )
                    {
                        c.OnConnectionLost( monitor );
                    }
                }
                _connectionAvailabilty = a;
                return _connectionAvailabilityChanged.SafeRaiseAsync( monitor, this );
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Gets whether this party is off line.
        /// Defaults to false: by default a remote always tries to establish a connection.
        /// </summary>
        public bool IsOff => _switchOffReason != null;

        /// <summary>
        /// Gets a non null string if this remote is off.
        /// </summary>
        public string? SwitchOffReason => ReferenceEquals( _switchOffReason, string.Empty ) ? "Torn down." : _switchOffReason;

        /// <summary>
        /// Switch this remote off.
        /// </summary>
        /// <param name="reason">A required non empty reason string.</param>
        /// <returns>True if this call switched this off, false if it was already off.</returns>
        public bool SwitchOff( string reason )
        {
            // The reason cannot be the empty string.
            Throw.CheckNotNullOrEmptyArgument( reason );
            if( Interlocked.CompareExchange( ref _switchOffReason, reason, null ) == null )
            {
                // We transitioned from null to this reason.
                // We don't rely on the _switchOffReason state:
                // the reason will flow to the DoSwitchOff method.
                _transportManager.SwitchOff( this, reason );
                return true;
            }
            return false;
        }

        /// <summary>
        /// Switch this remote on.
        /// </summary>
        /// <returns>False if this is definitely off.</returns>
        public bool SwitchOn()
        {
            // We never transition from the empty string reason to null: this is the definite off reason.
            var reason = _switchOffReason;
            if( reason == String.Empty ) return false;
            // Clear the off reason.
            // DoSwitchOn we'll do nothing if SwitchOff has been called.
            _switchOffReason = null;
            _transportManager.SwitchOn( this );
            return true;
        }

        internal void SetTornDownSwitchOff() => Interlocked.Exchange( ref _switchOffReason, string.Empty );

        /// <summary>
        /// Gets the last received time (<see cref="DateTimeKind.Utc"/>).
        /// </summary>
        public DateTime LastReceived => _controller != null ? _controller.CurrentTransport.LastReceived : Util.UtcMinValue;

        /// <summary>
        /// Gets the current connection availability.
        /// </summary>
        public ConnectionAvailability ConnectionAvailability => _connectionAvailabilty;

        /// <summary>
        /// Raised whenever this <see cref="ConnectionAvailability"/> changed.
        /// </summary>
        public PerfectEvent<TransportFeature> ConnectionAvailabilityChanged => _connectionAvailabilityChanged.PerfectEvent;


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
                monitor.Error( $"Unable to register '{channelFeatureName}'. There is already {MessageProtocolMap.MaxCount} channels registered for remote '{_party.FullName}'." );
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
                        monitor.Error( $"Channel '{channelFeatureName}' for remote '{_party.FullName}': protocol '{messageProtocol.FullName}' is already managed by another channel." );
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
                monitor.Warn( $"No message protocol registered for '{_party.FullName}'. You may want to disallow the \"TransportLayer\" feature." );
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
        /// Gets the remote party.
        /// </summary>
        public IRemoteParty Party => _party;

        /// <summary>
        /// Gets whether we are listening or targeting the remote.
        /// </summary>
        [MemberNotNullWhen( false, nameof( TargetAddress ) )]
        public bool IsListening => _listener != null;

        /// <summary>
        /// Gets the non null target address if <see cref="IsListening"/> is false.
        /// </summary>
        public TransportTypeAddress? TargetAddress => _target;

        /// <summary>
        /// Gets the local keys manager.
        /// </summary>
        public ILocalKeys LocalKeys => _localKeys;

        /// <summary>
        /// Gets the remote keys manager.
        /// </summary>
        public IRemoteKeys RemoteKeys => _remoteKeys;

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
        /// <para>
        /// To support dynamic key renewal, we check that the <see cref="IncomingMessage.LocalIdentities"/>
        /// is the same as the <see cref="ILocalKeys.Identities"/>.
        /// </para>
        /// </summary>
        internal InitialMessage? OutgoingInitialMessage
        {
            get
            {
                var m = _outgoingInitialMessage;
                if( m != null && m.LocalIdentities != _localKeys.Identities )
                {
                    m = _outgoingInitialMessage = new InitialMessage( this );
                }
                return m;
            }
        }

        internal void InitializeOutgoingAndInitiateConnection()
        {
            Debug.Assert( _target != null );
            _outgoingInitialMessage = new InitialMessage( this );
            _transportManager.TryConnectTo( this );
        }

        internal TransportController? TransportController => _controller;


        /// <summary>
        /// Calls to SwitchOn/SwitchOff are serialized (by the TransportManager).
        /// We skip a SwitchOn here that has been "canceled" by a call to SwitchOff:
        /// either this new SwitchOff state is the definite one (empty string) and we are done
        /// or a subsequent call to DoSwitchOn will be serialized.
        /// </summary>
        internal ValueTask DoSwitchOnAsync( IActivityMonitor monitor )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ) );
            var offReason = SwitchOffReason;
            if( _switchOffReason != null )
            {
                monitor.Trace( $"Remote '{Party.FullName}' is off (reason: '{offReason}'). Skipping its activation." );
            }
            else
            {
                monitor.Trace( $"Switching remote '{Party.FullName}' on." );
                if( _listener != null )
                {
                    _listener.AddParty( this );
                }
                else
                {
                    _transportManager.TryConnectTo( this );
                }
            }
            return default;
        }

        /// <summary>
        /// Do not challenge the switch off reason here, applies the originating offReason.
        /// We can safely miss a SwitchOn (above) because:
        ///  - _listener.RemoveParty is idempotent.
        ///  - If the controller is null, we do nothing.
        /// => This whole function is idempotent.
        /// </summary>
        internal async ValueTask DoSwitchOffAsync( IActivityMonitor monitor, string offReason )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ) );
            monitor.Trace( $"Switching remote '{Party.FullName}' off (reason: '{offReason}')." );
            _listener?.RemoveParty( this );
            var c = _controller;
            _controller = null;
            if( c != null )
            {
                // Setup a new ready task only if necessary.
                if( _readyTask.Task.IsCompleted ) _readyTask = new TaskCompletionSource();
                await c.CloseAsync( monitor, offReason );
            }
            await UpdateConnectionAvailabilityAsync( monitor );
            // When tearing down or not, raises the TransportManagerFeature event: IsOff has changed
            // and/or this is destroyed.
            await _transportManager.Feature._transportFeatureChangedEvent.SafeRaiseAsync( monitor, this );
            // When tearing down, dispose the connection availability event bridge.
            if( offReason.Length == 0 )
            {
                Debug.Assert( _switchOffReason != null && _switchOffReason.Length == 0 );
                _connectionEventBridge.Dispose();
            }
        }

        public override string ToString() => $"TransportFeature for '{_party.FullName}'";

    }

}
