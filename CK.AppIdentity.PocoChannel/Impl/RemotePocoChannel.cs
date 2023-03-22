using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.PerfectEvent;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;

namespace CK.AppIdentity.PocoChannel
{
    sealed class RemotePocoChannel : IPocoChannel
    {
        readonly IRemoteParty _remote;
        readonly IPEndPoint? _listenIP;
        readonly IPEndPoint? _targetIP;
        readonly PerfectEventSender<IPocoChannel> _isConnectedChanged;
        readonly PerfectEventSender<IPocoChannel, IPoco> _receivedPoco;

        /// <summary>
        /// The transport is under control of the ConnectionManager agent.
        /// </summary>
        ITransport? _transport;

        public RemotePocoChannel( IRemoteParty remote, IPEndPoint? listenIP, IPEndPoint? targetIP )
        {
            Debug.Assert( (listenIP == null) != (targetIP == null) );
            _remote = remote;
            _listenIP = listenIP;
            _targetIP = targetIP;
            _isConnectedChanged = new PerfectEventSender<IPocoChannel>();
            _receivedPoco = new PerfectEventSender<IPocoChannel, IPoco>();
        }

        public bool IsConnected => _transport != null;

        public IRemoteParty Party => _remote;

        public PerfectEvent<IPocoChannel> IsConnectedChanged => _isConnectedChanged.PerfectEvent;

        public PerfectEvent<IPocoChannel, IPoco> ReceivedPoco => _receivedPoco.PerfectEvent;

        public ValueTask<StoredPocoHandle> SendAsync( IActivityMonitor monitor, IPoco poco, bool store = false )
        {
            if( store ) throw new NotImplementedException();
            CreateTransportMessage( poco );

            return default;
        }

       private TransportMessage CreateTransportMessage( IPoco poco )
        {
            return null;
            //_connectionManager.MessageSendingFactory.Create( bytes =>
            //{
            //    using var w = new System.Text.Json.Utf8JsonWriter( bytes );
            //    poco.Write( w );
            //} );
        }

        public ValueTask<IPoco?> LoadAsync( in StoredPocoHandle handle )
        {
            throw new NotImplementedException();
        }

    }
}
