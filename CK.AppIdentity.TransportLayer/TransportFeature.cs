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
    public sealed class TransportFeature
    {
        readonly TransportManager _transportManager;
        readonly IRemoteParty _remote;
        readonly TransportListener? _listener;
        readonly PerfectEventSender<TransportFeature> _isConnectedChanged;
        // Channels are ordered like bestRegisteredProtocols.
        readonly List<ChannelFeature> _channels;
        // All available protocols with their versions.
        readonly HashSet<MessageProtocol> _registeredProtocols;
        // Available protocols with the highest version.
        readonly List<MessageProtocol> _bestRegisteredProtocols;

        InitialMessage? _outgoingInitialMessage;

        OutgoingMessageQueue? _endPoint;
        bool _isConnected;

        internal TransportFeature( TransportManager transportManager, IRemoteParty remote, TransportListener? listener )
        {
            _transportManager = transportManager;
            _remote = remote;
            _listener = listener;
            _channels = new List<ChannelFeature>( MessageProtocolMap.MaxCount );
            _isConnectedChanged = new PerfectEventSender<TransportFeature>();
            _registeredProtocols = new HashSet<MessageProtocol>();
            _bestRegisteredProtocols = new List<MessageProtocol>( MessageProtocolMap.MaxCount );
        }

        internal async Task OnTransportAppearAsync( IActivityMonitor monitor, Transport transport, MessageProtocolMap protocols )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ), "Called from the TransportManager loop." );
            Debug.Assert( protocols.Protocols.Count == _bestRegisteredProtocols.Count );
            Debug.Assert( protocols.Protocols.Select( p => p.Name ).SequenceEqual( _bestRegisteredProtocols.Select( p => p.Name ), StringComparer.OrdinalIgnoreCase ) );

            if( _endPoint == null )
            {
                _endPoint = new OutgoingMessageQueue( _transportManager, this, transport );
            }
            else
            {
                // Ensures that the current transport is condemned.
                _endPoint.CurrentTransport.SetCondemned();
                _endPoint.Rebind( monitor, _transportManager, transport );
            }
            Debug.Assert( _endPoint.Feature == this );
            var protocolHandlers = new PeerProtocolHandler[_bestRegisteredProtocols.Count];
            for( int i = 0; i < protocolHandlers.Length; i++ )
            {
                var c = _channels[i];
                Debug.Assert( c != null );
                protocolHandlers[i] = c.EnsureHandler( monitor, _endPoint, protocols.Protocols[i] );
            }
            transport.StartReceive( monitor, _transportManager, protocols, protocolHandlers );
            if( !_isConnected )
            {
                _isConnected = true;
                await _isConnectedChanged.SafeRaiseAsync( monitor, this );
            }
        }

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
                    _channels[i]._protocolNumber = i;
                }
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
        public PerfectEvent<TransportFeature> IsConnectedChanged => _isConnectedChanged.PerfectEvent;

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
        internal void Teardown( IActivityMonitor monitor )
        {
            // If we are not connected:
            //   - If the party is a caller, we don't have anything to do: the OutgoingConnectionBackTask
            //     tests the party.IsDestroyed and dies.
            //   - If we are listening we must remove this party from the listener.
            _listener?.RemoveParty( this );
            // Closing the transport is done from the transport manager loop.
            var e = _endPoint;
            if( e != null )
            {
                e.ClearPendingOutgoingMessages( monitor );
                if( !e.CurrentTransport.IsCondemned )
                {
                    _transportManager.CondemnTransport( e.CurrentTransport );
                }
            }
        }

    }

}
