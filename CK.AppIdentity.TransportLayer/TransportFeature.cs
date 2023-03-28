using CK.Core;
using CK.PerfectEvent;
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
        readonly HashSet<MessageProtocol> _availableProtocols;
        InitialMessage? _outgoingInitialMessage;

        /// <summary>
        /// The transport is under control of the TransportManager agent.
        /// </summary>
        ITransport? _transport;
        MessageProtocolMap _protocolMap;

        public TransportFeature( TransportManager transportManager, IRemoteParty remote, TransportListener? listener )
        {
            _transportManager = transportManager;
            _remote = remote;
            _listener = listener;
            _isConnectedChanged = new PerfectEventSender<TransportFeature>();
            _availableProtocols = new HashSet<MessageProtocol>();
        }

        internal Task OnNewTransportAsync( IActivityMonitor monitor, ITransport transport, MessageProtocolMap protocolMap )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ) );
            bool isConnected = _transport != null;
            if( isConnected ) _transportManager.CondemnTransport( _transport! );

            _transport = transport;
            _protocolMap = protocolMap;

            return isConnected != (transport != null)
                    ? _isConnectedChanged.SafeRaiseAsync( monitor, this )
                    : Task.CompletedTask;
        }

        /// <summary>
        /// Gets the registered protocols.
        /// </summary>
        public IReadOnlySet<MessageProtocol> AvailableProtocols
        {
            get
            {
                // This is updated during the initialization activity and accessed at the end
                // from FeatureInitializatonContext.Trampoline.OnSuccess to initiate
                // outgoing connections or register the listener party to its endpoint.
                // No one can see the feature from other activity than the initialization one
                // since the party and its features are not published until the initialization
                // activity fully succeeds: it is safe to expose it here.
                return _availableProtocols;
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
        public PerfectEvent<TransportFeature> IsConnectedChanged => _isConnectedChanged.PerfectEvent;

        /// <summary>
        /// Registers a <see cref="MessageProtocol"/> that must be handled by this transport.
        /// This can be called only during party initialization.
        /// </summary>
        /// <param name="monitor">The monitor.</param>
        /// <param name="protocol">The protocol that must be supported.</param>
        /// <returns>True on success, false if registering is not possible because the protocol is already registered.</returns>
        public bool RegisterProtocol( IActivityMonitor monitor, MessageProtocol protocol )
        {
            Throw.CheckArgument( protocol.IsValid && protocol != MessageProtocol.ZeroProtocol );
            Throw.CheckState( "Must be called only during initialization.", _transportManager.IsInApplicationIdentityLoop( monitor ) );
            if( !_availableProtocols.Add( protocol ) )
            {
                monitor.Error( $"Protocol '{protocol}' is already registered for remote '{_remote.FullName}'." );
                return false;
            }
            return true;
        }

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
