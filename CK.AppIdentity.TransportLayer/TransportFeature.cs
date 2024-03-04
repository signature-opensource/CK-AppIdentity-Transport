using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Centralizes communication feature for a remote.
    /// This feature is available only on a <see cref="IRemoteParty"/>. 
    /// </summary>
    public sealed class TransportFeature
    {
        readonly TransportManager _transportManager;
        readonly IRemoteParty _party;

        // Either listeners or target is not null.
        readonly TransportListener[]? _listeners;

        readonly TransportTypeAddress? _target;

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

        GoodbyeMessage? _switchOffReason;
        TransportController? _controller;
        TaskCompletionSource _readyTask;
        ConnectionAvailability _connectionAvailabilty;
        TimeSpan? _clockOffset;
        bool _disallowEviction;

        internal TransportFeature( TransportManager transportManager,
                                   IRemoteParty remote,
                                   TransportListener[]? listeners,
                                   TransportTypeAddress? target,
                                   IRemoteKeys remoteKeys,
                                   bool disallowEviction )
        {
            Throw.DebugAssert( "Either we are listening or we are targeting.", ( listeners == null) != (target == null) );
            _transportManager = transportManager;
            _party = remote;
            _listeners = listeners;
            _remoteKeys = remoteKeys;
            _target = target;
            _channels = new List<ChannelFeature>( MessageProtocolMap.MaxCount );

            _connectionAvailabilityChanged = new PerfectEventSender<TransportFeature>();
            _connectionEventBridge = _connectionAvailabilityChanged.CreateRelay( _transportManager.Feature._connectionAvailabilityChanged );

            _registeredProtocols = new HashSet<MessageProtocol>();
            _bestRegisteredProtocols = new List<MessageProtocol>( MessageProtocolMap.MaxCount );
            _readyTask = new TaskCompletionSource();
            _disallowEviction = disallowEviction;
        }

        internal async Task OnTransportAppearAsync( IActivityMonitor monitor,
                                                    Transport transport,
                                                    MessageProtocolMap protocols,
                                                    TimeSpan clockOffset,
                                                    GoodbyeMessage.Evicted? evictionMessage )
        {
            Throw.DebugAssert( "Called from the TransportManager loop.", _transportManager.IsInLoop( monitor ) );
            Throw.DebugAssert( protocols.Protocols.Count == _bestRegisteredProtocols.Count );
            Throw.DebugAssert( protocols.Protocols.Select( p => p.Name ).SequenceEqual( _bestRegisteredProtocols.Select( p => p.Name ), StringComparer.OrdinalIgnoreCase ) );

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
                _controller.Rebind( monitor, transport, evictionMessage );
            }
            Throw.DebugAssert( _controller.Feature == this );
            // Sets the ClockOffset.
            _clockOffset = clockOffset;
            // Second, ensures that protocol handlers for the right version are available
            // and are set to be the current one.
            var protocolHandlers = new PeerProtocolHandler[_bestRegisteredProtocols.Count];
            for( int i = 0; i < protocolHandlers.Length; i++ )
            {
                var c = _channels[i];
                Throw.DebugAssert( c != null );
                protocolHandlers[i] = c.EnsureCurrentHandler( monitor, _controller, protocols.Protocols[i] );
            }
            // The protocols are available (there may be no protocols).
            // We start receiving messages from this new transport (this sets the protocol map and handlers on the transport)
            // and starts sending the messages in the controller queues.
            await _controller.ActivateAsync( monitor, protocols, protocolHandlers ).ConfigureAwait( false );
            // Signals the change of connection before signaling the ready task: awaiting
            // the ready task and reading the availability is rather common initialization pattern.
            await UpdateExtremeConnectionAvailabilityAsync( monitor ).ConfigureAwait( false );
            // Always signals the ready task.
            _readyTask.TrySetResult();
        }

        Task UpdateExtremeConnectionAvailabilityAsync( IActivityMonitor monitor )
        {
            Throw.DebugAssert( "Called from the TransportManager loop.", _transportManager.IsInLoop( monitor ) );

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

        internal Task SetMaxConnectionAvailabilityAsync( IActivityMonitor monitor, ConnectionAvailability max )
        {
            Throw.DebugAssert( "Called from the TransportManager loop.", _transportManager.IsInLoop( monitor ) );
            if( _connectionAvailabilty > max )
            {
                _connectionAvailabilty = max;
                return _connectionAvailabilityChanged.SafeRaiseAsync( monitor, this );
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Gets whether this party is off line. The <see cref="Party"/> may be destroyed.
        /// Initially defaults to false: by default a remote always tries to establish a connection.
        /// <para>
        /// There is currently no "InitiallySwitchedOff" configuration.
        /// </para>
        /// </summary>
        public bool IsOff => _switchOffReason != null;

        internal GoodbyeMessage? SwitchOffMessage => _switchOffReason;

        /// <summary>
        /// Gets a non null string if this remote is off.
        /// This is "PartyDestoyed" when this <see cref="Party"/> is destroyed
        /// and "ApplicationIdentityShutdown" when the whole service is disposed.
        /// </summary>
        public string? SwitchOffReason => _switchOffReason switch
                                            {
                                                GoodbyeMessage.SwitchedOff m => m.Reason,
                                                GoodbyeMessage.PartyDestroyed => nameof( GoodbyeMessage.PartyDestroyed ),
                                                GoodbyeMessage.ApplicationIdentityShutdown => nameof( GoodbyeMessage.ApplicationIdentityShutdown ),
                                                GoodbyeMessage.Evicted e => e.ToString(),
                                                _ => null
                                            };

        internal bool RemoteSwitchedOff( GoodbyeMessage remoteMessage )
        {
            Throw.DebugAssert( remoteMessage.IsFromRemote
                               && (remoteMessage is GoodbyeMessage.Evicted
                                  || (remoteMessage is GoodbyeMessage.SwitchedOff off && off.ExpectedAvailableTime == Util.UtcMaxValue)) );
            return SetSwitchOffMessageOnlyOnce( remoteMessage );
        }

        /// <summary>
        /// Switch this remote off.
        /// </summary>
        /// <param name="reason">A required non empty reason string. Must not be longer than 255 characters.</param>
        /// <param name="expectedAvailableTime">Time at wich this transport should be back online. Must be <see cref="DateTimeKind.Utc"/>.</param>
        /// <returns>True if this call switched this off, false if it was already off.</returns>
        public bool SwitchOff( string reason, DateTime? expectedAvailableTime = null )
        {
            // The reason cannot be the empty string, cannot be longer than 255 characters and
            // cannot be the 2 reserved messages.
            // We normalize it as it appears in the 0 Protocol.
            Throw.CheckNotNullOrEmptyArgument( reason );
            reason = reason.Normalize();
            Throw.CheckArgument( reason.Length < 256 );
            Throw.CheckArgument( reason != nameof( GoodbyeMessage.PartyDestroyed ) && reason != nameof( GoodbyeMessage.ApplicationIdentityShutdown ) );
            Throw.CheckArgument( expectedAvailableTime?.Kind is null or DateTimeKind.Utc );
            return SetSwitchOffMessageOnlyOnce( new GoodbyeMessage.SwitchedOff( false, reason, expectedAvailableTime ) );
        }

        bool SetSwitchOffMessageOnlyOnce( GoodbyeMessage goodbye )
        {
            if( Interlocked.CompareExchange( ref _switchOffReason, goodbye, null ) == null )
            {
                // We transitioned from null to this reason.
                // We don't rely on the _switchOffReason state:
                // the reason will flow to the DoSwitchOff method.
                _transportManager.SwitchOff( this, goodbye );
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
            // We never transition from local PartyDestroyed or ApplicationIdentityShutDown to null:
            // these are definite off reason.
            retry:
            var reason = _switchOffReason;
            if( reason != null
                && !reason.IsFromRemote
                && reason.Kind is GoodbyeKind.PartyDestroyed or GoodbyeKind.ApplicationIdentityShutdown )
            {
                return false;
            }
            if( Interlocked.CompareExchange( ref _switchOffReason, null, reason ) != reason ) goto retry;
            // Clear the off reason.
            // DoSwitchOn we'll do nothing if SwitchOff has been called.
            _transportManager.SwitchOn( this );
            return true;
        }

        internal void SetTornDownSwitchOff( GoodbyeMessage reason ) => Interlocked.Exchange( ref _switchOffReason, reason );

        /// <summary>
        /// Gets the last received time.
        /// Defaults to <see cref="Util.UtcMinValue"/>.
        /// </summary>
        public DateTime LastReceived => _controller != null ? _controller.CurrentTransport.LastReceived : Util.UtcMinValue;

        /// <summary>
        /// Gets the current connection availability.
        /// </summary>
        public ConnectionAvailability ConnectionAvailability => _connectionAvailabilty;

        /// <summary>
        /// Gets the last known clock offset between us and the remote.
        /// </summary>
        public TimeSpan? ClockOffset => _clockOffset;

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
                Throw.DebugAssert( "This is safe: see CloseChannelRegistration comment.", _bestRegisteredProtocols != null );
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
                Throw.DebugAssert( "This is safe: see CloseChannelRegistration comment.", _bestRegisteredProtocols != null );
                return _registeredProtocols;
            }
        }

        internal bool RegisterChannel( IActivityMonitor monitor,
                                       ChannelFeature channel,
                                       string channelFeatureName,
                                       string protocolName,
                                       IEnumerable<ushort> protocolVersions )
        {
            Throw.DebugAssert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
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
            Throw.DebugAssert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            Throw.DebugAssert( _channels.Take( _bestRegisteredProtocols.Count ).All( c => c != null ) );
            Throw.DebugAssert( _channels.Skip( _bestRegisteredProtocols.Count ).All( c => c == null ) );
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
        [MemberNotNullWhen( true, nameof( Listeners ) )]
        public bool IsListening => _listeners != null;

        /// <summary>
        /// Gets the non null listeners if <see cref="IsListening"/> is false.
        /// </summary>
        public IReadOnlyCollection<TransportListener>? Listeners => _listeners;

        /// <summary>
        /// Gets the non null target address if <see cref="IsListening"/> is false.
        /// </summary>
        public TransportTypeAddress? TargetAddress => _target;

        /// <summary>
        /// Gets the remote keys manager that gives access to the <see cref="IRemoteKeys.LocalKeys"/>.
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
                // We cannot reuse the cached message if:
                // - Our owner's identity keys have changed.
                // - Or our knowledge of the remote's identity has changed. 
                if( m == null
                    || m.LocalIdentities != _remoteKeys.LocalKeys.Identities
                    || HasChanged( m.RemoteTrustInfo.SupposedIdentity, _remoteKeys.TrustedIdentity )
                    || m.RemoteTrustInfo.CanAutoTrust != (_remoteKeys.AutoTrustKey == AutoTrustKey.Always
                                                          || (_remoteKeys.AutoTrustKey == AutoTrustKey.Once && _remoteKeys.TrustedIdentity == null)) )
                {
                    m = _outgoingInitialMessage = new InitialMessage( this );
                }
                return m;

                static bool HasChanged( RemoteIdentityKeyData? supposedIdentity, RemoteIdentityKey? trustedIdentity )
                {
                    if( trustedIdentity == null )
                    {
                        return supposedIdentity != null;
                    }
                    return !trustedIdentity.Equals( supposedIdentity );
                }
            }
        }

        internal void InitializeOutgoingAndInitiateConnection()
        {
            Throw.DebugAssert( _target != null );
            _outgoingInitialMessage = new InitialMessage( this );
            _transportManager.TryConnectTo( this );
        }

        internal TransportController? TransportController => _controller;


        /// <summary>
        /// Calls to SwitchOn/SwitchOff are serialized (by the TransportManager).
        /// We skip a SwitchOn here that has been "canceled" by a call to SwitchOff:
        /// either this new SwitchOff state is the definite PartyDestroyed or ApplicationIdentityShutdown
        /// and we are done or a subsequent call to DoSwitchOn will be serialized.
        /// </summary>
        internal ValueTask DoSwitchOnAsync( IActivityMonitor monitor )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            if( _switchOffReason != null )
            {
                monitor.Trace( $"Remote '{Party.FullName}' is off ({_switchOffReason}). Skipping its activation." );
            }
            else
            {
                monitor.Trace( $"Switching remote '{Party.FullName}' ON." );
                if( _listeners == null )
                {
                    _transportManager.TryConnectTo( this );
                }
                else
                {
                    // We have nothing to do for listeners. This party still
                    // appears in the associated listeners because it has not
                    // been "definitly" shutdown, just "regularly" shutdown.
                    Throw.DebugAssert( _listeners.All( l => l.Parties.Contains( this ) ) );
                }
            }
            return default;
        }

        /// <summary>
        /// Do not challenge the _switchOffReason here, applies the originating offReason.
        /// We can safely miss a SwitchOn (above) because:
        ///  - If the controller is null, we do nothing.
        ///  - _listener.RemoveParty is idempotent.
        /// => This whole function is idempotent.
        /// </summary>
        internal async ValueTask DoSwitchOffAsync( IActivityMonitor monitor, TaskCompletionSource? done, GoodbyeMessage offReason )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            // The "Definitive" switch off:
            Throw.DebugAssert( "The TCS is provided if and only if we are tearing down the party.",
                               (done != null) == (!offReason.IsFromRemote && offReason.Kind is GoodbyeKind.PartyDestroyed or GoodbyeKind.ApplicationIdentityShutdown) );

            monitor.Trace( $"Switching remote '{Party.FullName}' OFF: {offReason}" );
            var c = _controller;
            _controller = null;
            if( c != null )
            {
                // Setup a new ready task only if necessary.
                if( _readyTask.Task.IsCompleted ) _readyTask = new TaskCompletionSource();
                await c.CloseAsync( monitor, offReason ).ConfigureAwait( false );
            }
            await UpdateExtremeConnectionAvailabilityAsync( monitor ).ConfigureAwait( false );
            // When tearing down or not, raises the TransportManagerFeature event: IsOff has changed
            // and/or this is destroyed.
            await _transportManager.Feature._transportFeatureChangedEvent.SafeRaiseAsync( monitor, this ).ConfigureAwait( false );
            // When tearing down, dispose the connection availability event bridge.
            if( done != null )
            {
                // Update the possible PeeringIssue if any.
                await _transportManager.Feature.OnRemoteTornDownAsync( monitor, this ).ConfigureAwait( false );
                _connectionEventBridge.Dispose();
                done.SetResult();
            }
        }

        public override string ToString() => $"TransportFeature for '{_party.FullName}'";

    }

}
