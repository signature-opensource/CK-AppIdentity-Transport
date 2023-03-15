using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.PocoChannel
{
    sealed partial class ConnectionManager : MicroAgent
    {
        readonly AppIdentityAgent _agent;
        IncomingConnections _incoming;
        List<TcpSocketListener> _tcpListeners;
        readonly Timer _heartbeat;

        sealed class IncomingConnections
        {
            readonly List<KeyValuePair<Transport, Task<string?>>> _incomingConnections;

            public IncomingConnections()
            {
                _incomingConnections = new();
            }

            public void Add( Transport t )
            {
                _incomingConnections.Add( KeyValuePair.Create( t, ValidateAsync( t ) ) );
            }

            Task<string?> ValidateAsync( Transport t )
            {
                return null!;
            }
        }

        public ConnectionManager( AppIdentityAgent agent )
            : base( "CK.AppIdentity.PocoChannel.ConnectionManager" )
        {
            _agent = agent;
            _tcpListeners = new List<TcpSocketListener>();
            _heartbeat = new Timer( OnTimer, this, 1000, 1000 );
        }

        static void OnTimer( object? state ) => Unsafe.As<ConnectionManager>( state! ).PushTypedJob( DBNull.Value );

        public bool Start() => TryStart() == RunningStatus.Running;

        public bool RegisterTcpListenerParty( IActivityMonitor monitor, IPEndPoint endPoint, IRemoteParty remote )
        {
            lock( _tcpListeners )
            {
                foreach( var exists in _tcpListeners )
                {
                    if( endPoint.Equals( exists.Address ) || endPoint.Equals( exists.ActualListeningAddress ) )
                    {
                        exists.AddParty( remote );
                        return true;
                    }
                }
                var l = TryCreate( monitor, endPoint, remote );
                if( l == null ) return false;
                _tcpListeners.Add( l );
                return true;
            }
        }

        public void OnListenerPartyDestroy( IActivityMonitor monitor, IRemoteParty remote )
        {
            Debug.Assert( remote.Address == null );

        }


        TcpSocketListener? TryCreate( IActivityMonitor monitor, IPEndPoint endPoint, IRemoteParty firstParty )
        {
            try
            {
                Socket socket;
                if( endPoint.Address == IPAddress.Any && Socket.OSSupportsIPv6 )
                {
                    socket = new Socket( AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp );
                    socket.DualMode = true;
                    endPoint.Address = IPAddress.IPv6Any;
                }
                else
                {
                    socket = new Socket( endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp );
                }
                socket.Bind( endPoint );
                socket.Listen();
                Debug.Assert( socket.LocalEndPoint is IPEndPoint );
                return new TcpSocketListener( this, endPoint, socket, firstParty );
            }
            catch( Exception ex )
            {
                monitor.Error( $"While creating TCP socket listener on '{endPoint}'.", ex );
                return null;
            }
        }

        void OnIncomingConnection( Transport t ) => PushTypedJob( t );

        protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case Transport t:
                    _incoming.Add( t );
                    return default;
                case DBNull: return OnHeartBeat( monitor );
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        ValueTask OnHeartBeat( IActivityMonitor monitor )
        {
            return default;
        }

    }
}
