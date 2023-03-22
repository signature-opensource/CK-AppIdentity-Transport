using CK.Core;
using CK.PerfectEvent;
using System.Net;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// 
    /// </summary>
    public class TransportFeature
    {
        readonly TransportManager _transportManager;
        readonly IRemoteParty _remote;
        readonly PerfectEventSender<TransportFeature> _isConnectedChanged;

        /// <summary>
        /// The transport is under control of the TransportManager agent.
        /// </summary>
        ITransport? _transport;

        public TransportFeature( TransportManager transportManager, IRemoteParty remote )
        {
            _transportManager = transportManager;
            _remote = remote;
            _isConnectedChanged = new PerfectEventSender<TransportFeature>();
        }

        internal void OnNewTransport( IActivityMonitor monitor, ITransport transport )
        {
            if( _transport != null ) _transportManager.PushTypedJob( new TransportManager.CondemnTransportJob( _transport ) );
            _transport = transport;
        }

        public bool IsConnected => _transport != null;

        public IRemoteParty Party => _remote;

        public PerfectEvent<TransportFeature> IsConnectedChanged => _isConnectedChanged.PerfectEvent;
    }

}
