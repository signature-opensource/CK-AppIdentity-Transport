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
        readonly HashSet<MessageProtocol> _registeredProtocols;
        IReadOnlyCollection<MessageProtocol>? _bestRegisteredProtocols;
        InitialMessage? _outgoingInitialMessage;
        internal MessageProtocolFeature? _firstProtocol;

        /// <summary>
        /// The transport is under control of the TransportManager agent.
        /// </summary>
        ITransport? _transport;

        internal TransportFeature( TransportManager transportManager, IRemoteParty remote, TransportListener? listener )
        {
            _transportManager = transportManager;
            _remote = remote;
            _listener = listener;
            _isConnectedChanged = new PerfectEventSender<TransportFeature>();
            _registeredProtocols = new HashSet<MessageProtocol>();
        }

        internal Task OnNewTransportAsync( IActivityMonitor monitor, ITransport transport )
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
        public IReadOnlyCollection<MessageProtocol> BestRegisteredProtocols
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

        /// <summary>
        /// The _registeredProtocols is updated during the initialization activity and
        /// this is called at the end by FeatureInitializatonContext.Trampoline.OnSuccess.
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
            Debug.Assert( _bestRegisteredProtocols == null, "Closed only once." );
            var a = _registeredProtocols.GroupBy( p => p.Name )
                                        .Select( g => g.MaxBy( g => g.Version ) )
                                        .ToArray();
            if( a.Length == 0 )
            {
                monitor.Warn( $"No message protocol registered for '{_remote.FullName}'. You may want to disallow the \"TransportLayer\" feature." );
            }
            _bestRegisteredProtocols = a!;
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

        internal bool RegisterProtocol( IActivityMonitor monitor, MessageProtocol protocol )
        {
            Debug.Assert( _transportManager.IsInApplicationIdentityLoop( monitor ), "Must be called only during initialization." );
            if( _registeredProtocols.Count == InitialMessage.MaxProtocolFullNameCount )
            {
                monitor.Error( $"Unable to register protocol '{protocol}'. There is already {InitialMessage.MaxProtocolFullNameCount} protocols registered for remote '{_remote.FullName}'." );
                return false;
            }
            if( !_registeredProtocols.Add( protocol ) )
            {
                monitor.Error( $"Protocol '{protocol}' is already registered for remote '{_remote.FullName}'." );
                return false;
            }
            return true;
        }

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
