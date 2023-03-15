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
        Socket? _socket;

        public RemotePocoChannel( IRemoteParty remote, IPEndPoint? listenIP, IPEndPoint? targetIP )
        {
            Debug.Assert( (listenIP == null) != (targetIP == null) );
            _remote = remote;
            _listenIP = listenIP;
            _targetIP = targetIP;
            _isConnectedChanged = new PerfectEventSender<IPocoChannel>();
            _receivedPoco = new PerfectEventSender<IPocoChannel, IPoco>();
        }

        public bool IsConnected => _socket != null;

        public IRemoteParty Party => _remote;

        public PerfectEvent<IPocoChannel> IsConnectedChanged => _isConnectedChanged.PerfectEvent;

        public PerfectEvent<IPocoChannel, IPoco> ReceivedPoco => _receivedPoco.PerfectEvent;

        public ValueTask<StoredPocoHandle> SendAsync( IActivityMonitor monitor, IPoco poco, bool store = false )
        {
            if( store ) throw new NotImplementedException();

            return default;
        }

        public ValueTask<IPoco?> LoadAsync( in StoredPocoHandle handle )
        {
            throw new NotImplementedException();
        }

    }
}
