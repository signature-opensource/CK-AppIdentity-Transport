using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections;
using System.Diagnostics;
using System.Net;

namespace CK.AppIdentity.TransportLayer
{

    /// <summary>
    /// 
    /// </summary>
    public sealed class TransportLayerFeature
    {
        readonly TransportManager _transportManager;
        readonly IRemoteParty _remote;
        readonly TransportListener? _listener;
        readonly PerfectEventSender<TransportLayerFeature> _isConnectedChanged;
        // Preallocated array of MessageProtocolMap.MaxCount (7).
        readonly ChannelFeature?[] _channels;
        // All available protocols with their versions.
        readonly HashSet<MessageProtocol> _registeredProtocols;
        // Available protocols with the highest version.
        readonly List<MessageProtocol> _bestRegisteredProtocols;
        readonly ListeningMode _listeningMode;
        readonly ILiveMessageEndPointCollection _endPoints;

        InitialMessage? _outgoingInitialMessage;

        MessageEndPoint? _firstEndPoint;
        int _endPointCount;
        bool _isConnected;

        internal TransportLayerFeature( TransportManager transportManager, IRemoteParty remote, TransportListener? listener, ListeningMode listeningMode )
        {
            _transportManager = transportManager;
            _remote = remote;
            _listener = listener;
            _listeningMode = listeningMode;
            _channels = new ChannelFeature[MessageProtocolMap.MaxCount];
            _isConnectedChanged = new PerfectEventSender<TransportLayerFeature>();
            _registeredProtocols = new HashSet<MessageProtocol>();
            _bestRegisteredProtocols = new List<MessageProtocol>();
            _endPoints = new LiveEnumerator( this );
        }

        internal async Task OnTransportAppearAsync( IActivityMonitor monitor, Transport transport, MessageProtocolMap protocols )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ), "Called from the TransportManager loop." );
            Debug.Assert( protocols.Protocols.Count == _bestRegisteredProtocols.Count );
            Debug.Assert( protocols.Protocols.Select( p => p.Name ).SequenceEqual( _bestRegisteredProtocols.Select( p => p.Name ), StringComparer.OrdinalIgnoreCase ) );

            MessageEndPoint? newOne = null;
            if( _firstEndPoint == null )
            {
                _firstEndPoint = newOne = new MessageEndPoint( _transportManager, this, transport );
            }
            else if( _listeningMode == ListeningMode.Default )
            {
                // If the current endpoint is still alive (this means we are a server because if we were
                // a client a new transport only pops when the current one is dead, but we don't really care here),
                // we signal its end and immediately tell the channels about this killing.
                if( _firstEndPoint.IsConnected )
                {
                    _firstEndPoint.Transport.SetCondemned();
                    await OnTransportCondemnAsync( monitor, _firstEndPoint.Transport, potentialRecycling: transport );
                }
                _firstEndPoint.Rebind( monitor, _transportManager, transport );
            }
            else
            {
                newOne = new MessageEndPoint( _transportManager, this, transport );
                _firstEndPoint._prevEndPoint = _firstEndPoint;
                newOne._nextEndPoint = _firstEndPoint;
                // Important: publish the head after the nodes have been configured.
                _firstEndPoint = newOne;
            }
            if( newOne != null )
            {
                // For ListeningMode.Default, this definitely transitions _endPointCount from 0 to 1:
                // from now on, the endpoint will be rebound.
                ++_endPointCount;
                Debug.Assert( newOne.Feature == this );
            }
            var protocolHandlers = new IProtocolHandler[_bestRegisteredProtocols.Count];
            for( int i = 0; i < protocolHandlers.Length; i++ )
            {
                var c = _channels[i];
                Debug.Assert( c != null );
                protocolHandlers[i] = c.EnsureMessageHandler( monitor, protocols.Protocols[i] );
            }
            transport.StartReceive( monitor, _transportManager, protocols, protocolHandlers );
            if( !_isConnected )
            {
                _isConnected = true;
                await _isConnectedChanged.SafeRaiseAsync( monitor, this );
            }
        }

        internal async Task OnTransportCondemnAsync( IActivityMonitor monitor, Transport transport, Transport? potentialRecycling = null )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ), "Called from the TransportManager loop." );
            Debug.Assert( transport.Lifetime.IsCancellationRequested );
            // The condemned transport has been previously added:
            // - The endpoint has been set and is managed by this feature.
            // - The receivers have been set.
            Debug.Assert( transport.EndPoint != null 
                          && transport.EndPoint.Feature == this
                          && transport.Handlers != null );
            bool isNewConnected;
            // First, removes the endpoint from the list when in multiple mode. 
            if( _listeningMode == ListeningMode.Default )
            {
                isNewConnected = potentialRecycling != null;
            }
            else
            {
                Debug.Assert( potentialRecycling == null, "There is no recycling when in multiple mode." );
                isNewConnected = --_endPointCount > 0;
                var e = transport.EndPoint;
                // Skip the forward link first.
                var prev = e._prevEndPoint;
                if( prev != null ) prev._nextEndPoint = e._nextEndPoint;
                else _firstEndPoint = e._nextEndPoint;
                // Update the backward link.
                if( e._nextEndPoint != null ) e._nextEndPoint._prevEndPoint = prev;
                // Do NOT clear _nextEndPoint: this is the key point for the live enumerator
                // to be able to enumerate next endpoints from a dead one!
                e._prevEndPoint = null;
                // The disconnected end point doesn't appear anymore in the list.
                // Currently, we can only save the message if a remote with the same protocol version
                // is available (we use the MessageHandlers to TryEnqueue the messages).
                // If the messages cannot be transfered, they are disposed (0 protocol messages are always disposed).
                if( !_remote.IsDestroyed )
                {
                    e.HandlePendingOutgoingMessages( monitor );
                }
            }
            // Second, tell the handlers about the disconnected endpoint.  
            foreach( var r in transport.Handlers )
            {
                await r.OnDisconnectedAsync( monitor, transport.EndPoint, potentialRecycling );
            }
            if( _isConnected != isNewConnected )
            {
                _isConnected = isNewConnected;
                await _isConnectedChanged.SafeRaiseAsync( monitor, this );
            }
        }

        sealed class LiveEnumerator : ILiveMessageEndPointCollection
        {
            readonly TransportLayerFeature _f;

            public LiveEnumerator( TransportLayerFeature f ) => _f = f;

            public int Count => _f._endPointCount;

            public IEnumerator<MessageEndPoint> GetEnumerator()
            {
                var e = _f._firstEndPoint;
                while( e != null )
                {
                    if( e.IsConnected ) yield return e;
                    e = e._nextEndPoint;
                }
            }

            public MessageEndPoint? GetNext( MessageEndPoint? previous )
            {
                var n = previous?._nextEndPoint ?? _f._firstEndPoint;
                bool loop = false;
                while( n != null )
                {
                    if( n.IsConnected ) break;
                    n = n._nextEndPoint;
                    if( n == null )
                    {
                        if( loop ) break;
                        n = _f._firstEndPoint;
                        loop = true;
                    }
                }
                return n;
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

        /// <summary>
        /// Gets the <see cref="ListeningMode"/>.
        /// The <see cref="ListeningMode.Default"/> applies to clients and single party listeners.
        /// </summary>
        public ListeningMode ListeningMode => _listeningMode;

        /// <summary>
        /// Gets the set of currently connected endpoints. This is a "live" set:
        /// its count can change at anytime and a end point with a false <see cref="MessageEndPoint.IsConnected"/>
        /// can appear in the set.
        /// </summary>
        public ILiveMessageEndPointCollection LiveEndPoints => _endPoints;

        /// <summary>
        /// Gets the registered protocols with their best respective version among the
        /// available <see cref="RegisteredProtocols"/>.
        /// </summary>
        public IReadOnlyList<MessageProtocol> BestRegisteredProtocols
        {
            get
            {
                Debug.Assert( _bestRegisteredProtocols !=null, "This is safe: see CloseChannelRegistration comment." );
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

        internal int RegisterChannel( IActivityMonitor monitor,
                                      ChannelFeature channel,
                                      string channelFeatureName,
                                      string protocolName,
                                      IEnumerable<ushort> protocolVersions )
        {
            Debug.Assert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            if( _bestRegisteredProtocols.Count == MessageProtocolMap.MaxCount )
            {
                monitor.Error( $"Unable to register '{channelFeatureName}'. There is already {MessageProtocolMap.MaxCount} channels registered for remote '{_remote.FullName}'." );
                return -1;
            }
            int idxSorted;
            using var versions = protocolVersions.OrderByDescending( Util.FuncIdentity ).GetEnumerator();
            if( versions.MoveNext() )
            {
                idxSorted = RegisterBestProtocol( monitor, channelFeatureName, protocolName, versions.Current );
                if( idxSorted < 0 ) return -1;
                while( versions.MoveNext() )
                {
                    if( !_transportManager.MessageProtocolDirectory.TryRegister( monitor, protocolName, versions.Current, out var messageProtocol ) )
                    {
                        return -1;
                    }
                    if( !_registeredProtocols.Add( messageProtocol ) )
                    {
                        monitor.Error( $"Channel '{channelFeatureName}': duplicate protocol versions detected ({messageProtocol.FullName})." );
                        return -1;
                    }
                }
            }
            else
            {
                idxSorted = RegisterBestProtocol( monitor, channelFeatureName, protocolName, 0 );
                if( idxSorted < 0 ) return -1;
            }
            channel._baseProtocolName = protocolName;
            _channels[idxSorted] = channel;
            return idxSorted;
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
        }

        /// <summary>
        /// Gets whether this transport is connected to the other party.
        /// </summary>
        public bool IsConnected => _isConnected;

        /// <summary>
        /// Gets the party.
        /// </summary>
        public IRemoteParty Party => _remote;

        /// <summary>
        /// Raised whenever this <see cref="IsConnected"/> status changed.
        /// </summary>
        public PerfectEvent<TransportLayerFeature> IsConnectedChanged => _isConnectedChanged.PerfectEvent;

        /// <summary>
        /// Gets the initial message to send when this is a caller.
        /// This will be used each time a new connection must be acquired.
        /// </summary>
        internal InitialMessage? OutgoingInitialMessage => _outgoingInitialMessage;

        internal void InitializeOutgoing( TransportTypeAddress target )
        {
            _outgoingInitialMessage = new InitialMessage( this );
            _transportManager.TryConnectTo( this, target );
        }

        /// <summary>
        /// We don't want to expose any DisposeAsync or Dispose on this public TransportFeature.
        /// This is called when tearing down the remote party.
        /// </summary>
        internal void Teardown()
        {
            // If we are not connected:
            //   - If the party is a caller, we don't have anything to do: the OutgoingConnectionBackTask
            //     tests the party.IsDestroyed and dies.
            //   - If we are listening we must remove this party from the listener.
            _listener?.RemoveParty( this );
            // Closing the transport is done from the transport manager loop.
            var e = _firstEndPoint;
            while( e != null )
            {
                if( !e.Transport.IsCondemned ) _transportManager.CondemnTransport( e.Transport );
                e = e._nextEndPoint;
            }
        }

    }

}
