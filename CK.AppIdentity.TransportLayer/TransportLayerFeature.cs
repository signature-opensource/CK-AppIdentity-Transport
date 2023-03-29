using CK.Core;
using CK.PerfectEvent;
using System;
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
        readonly ChannelFeature?[] _channels;
        readonly HashSet<MessageProtocol> _registeredProtocols;
        readonly List<MessageProtocol> _bestRegisteredProtocols;

        InitialMessage? _outgoingInitialMessage;

        /// <summary>
        /// The transport is under control of the TransportManager agent.
        /// </summary>
        Transport? _transport;

        internal TransportLayerFeature( TransportManager transportManager, IRemoteParty remote, TransportListener? listener )
        {
            _transportManager = transportManager;
            _remote = remote;
            _listener = listener;
            _channels = new ChannelFeature[1+MessageProtocolMap.MaxCount];
            _isConnectedChanged = new PerfectEventSender<TransportLayerFeature>();
            _registeredProtocols = new HashSet<MessageProtocol>();
            _bestRegisteredProtocols = new List<MessageProtocol>();
        }

        internal Task OnNewTransportAsync( IActivityMonitor monitor, Transport transport )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ), "Called from the TransportManager loop." );

            bool isConnected = _transport != null;
            if( isConnected ) _transportManager.CondemnTransport( _transport! );

            _transport = transport;

            return isConnected != (transport != null)
                    ? _isConnectedChanged.SafeRaiseAsync( monitor, this )
                    : Task.CompletedTask;
        }

        /// <summary>
        /// Gets the registered protocols with their best respective version among the
        /// available <see cref="RegisteredProtocols"/>.
        /// </summary>
        public IReadOnlyList<MessageProtocol> BestRegisteredProtocols
        {
            get
            {
                Debug.Assert( _bestRegisteredProtocols !=null, "This is safe: see CloseRegisteredProtocols comment." );
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
                Debug.Assert( _bestRegisteredProtocols != null, "This is safe: see CloseRegisteredProtocols comment." );
                return _registeredProtocols;
            }
        }

        internal int RegisterChannel( IActivityMonitor monitor,
                                      ChannelFeature channel,
                                      string channelFeatureName,
                                      string protocolName,
                                      IEnumerable<ushort> protocolVersions,
                                      bool isPartySpecific )
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
                idxSorted = RegisterBestProtocol( monitor, channelFeatureName, protocolName, versions.Current, isPartySpecific );
                if( idxSorted < 0 ) return -1;
                while( versions.MoveNext() )
                {
                    if( !_transportManager.MessageProtocolDirectory.TryRegister( monitor, protocolName, versions.Current, isPartySpecific, out var messageProtocol ) )
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
                idxSorted = RegisterBestProtocol( monitor, channelFeatureName, protocolName, 0, isPartySpecific );
                if( idxSorted < 0 ) return -1;
            }
            _channels[++idxSorted] = channel;
            return idxSorted;
        }

        int RegisterBestProtocol( IActivityMonitor monitor, string channelFeatureName, string protocolName, ushort version, bool isPartySpecific )
        {
            if( _transportManager.MessageProtocolDirectory.TryRegister( monitor, protocolName, version, isPartySpecific, out var messageProtocol ) )
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
        internal void CloseRegisteredProtocols( IActivityMonitor monitor )
        {
            Debug.Assert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            if( _bestRegisteredProtocols.Count == 0 )
            {
                monitor.Warn( $"No message protocol registered for '{_remote.FullName}'. You may want to disallow the \"TransportLayer\" feature." );
            }
        }

        /// <summary>
        /// Gets whether this transport is connected to the other party.
        /// </summary>
        public bool IsConnected => _transport != null;

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
            if( _listener != null )
            {
                _listener.RemoveParty( this );
            }
            // Closing the transport should be done from the transport manager loop.
            var t = _transport;
            if( t != null ) _transportManager.CondemnTransport( t );
        }

    }

}
