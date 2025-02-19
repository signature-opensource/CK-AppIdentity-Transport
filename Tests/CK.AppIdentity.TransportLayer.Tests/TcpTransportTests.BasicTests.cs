using NUnit.Framework;
using System.Net.Sockets;
using System.Net;
using System.Threading.Tasks;
using System.Threading;
using FluentAssertions;

namespace CK.AppIdentity.TransportLayer.Tests;

public partial class TcpTransportTests
{
    [Test, CancelAfter( 7000 )]
    public async Task reopening_listener_Async( CancellationToken timeout )
    {
        for( int i = 0; i < 2; i++ )
        {
            var listenSocket = new Socket( AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp )
            {
                DualMode = true
            };
            var listenEndPoint = new IPEndPoint( IPAddress.IPv6Any, 37120 );
            listenSocket.Bind( listenEndPoint );
            listenSocket.Listen();

            var sendEndPoint = new IPEndPoint( IPAddress.IPv6Loopback, 37120 );

            var w1 = AcceptAndCloseIncomingConnectionAsync( listenSocket, timeout );
            await SendAndCloseAsync( sendEndPoint, 42, timeout ).ConfigureAwait( false );
            (await w1).Should().Be( 42 );

            var w2 = AcceptAndCloseIncomingConnectionAsync( listenSocket, timeout );
            await SendAndCloseAsync( sendEndPoint, 217, timeout ).ConfigureAwait( false );
            (await w2).Should().Be( 217 );

            listenSocket.Dispose();
        }
    }

    [Test, CancelAfter( 7000 )]
    public async Task reopening_listener_with_ingoing_connections_Async( CancellationToken timeout )
    {
        for( int i = 0; i < 2; i++ )
        {
            var listenSocket = new Socket( AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp )
            {
                DualMode = true
            };
            var listenEndPoint = new IPEndPoint( IPAddress.IPv6Any, 37120 );
            listenSocket.Bind( listenEndPoint );
            listenSocket.Listen();

            var sendEndPoint = new IPEndPoint( IPAddress.IPv6Loopback, 37120 );

            var openedConnection = new Socket( SocketType.Stream, ProtocolType.Tcp );
            await openedConnection.ConnectAsync( sendEndPoint, timeout ).ConfigureAwait( false );
            openedConnection.Send( new byte[] { 69 } );

            listenSocket.Dispose();
        }
    }

    [Test, CancelAfter( 7000 )]
    public async Task reopening_listener_with_pending_connections_Async( CancellationToken timeout )
    {
        for( int i = 0; i < 2; i++ )
        {
            var listenSocket = new Socket( AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp )
            {
                DualMode = true
            };
            var listenEndPoint = new IPEndPoint( IPAddress.IPv6Any, 37120 );
            listenSocket.Bind( listenEndPoint );
            listenSocket.Listen();

            var sendEndPoint = new IPEndPoint( IPAddress.IPv6Loopback, 37120 );

            var w1 = AcceptAndLeaveConnectionAsync( listenSocket, timeout );
            await SendAndCloseAsync( sendEndPoint, 42, timeout ).ConfigureAwait( false );
            (await w1).Should().Be( 42 );

            listenSocket.Dispose();
        }

        static async Task<byte> AcceptAndLeaveConnectionAsync( Socket listenSocket, CancellationToken timeout )
        {
            var acceptSocket = await listenSocket.AcceptAsync( timeout ).ConfigureAwait( false );
            acceptSocket.NoDelay = true; // Disable Nagle algorithm.
            var buffer = new byte[1];
            acceptSocket.Receive( buffer ).Should().Be( 1 );
            return buffer[0];
        }
    }

    static async Task SendAndCloseAsync( IPEndPoint ipEndPoint, byte v, CancellationToken timeout )
    {
        var s = new Socket( SocketType.Stream, ProtocolType.Tcp );
        await s.ConnectAsync( ipEndPoint, timeout ).ConfigureAwait( false );
        s.Send( new byte[] { v } );
        s.Dispose();
    }

    static async Task<byte> AcceptAndCloseIncomingConnectionAsync( Socket listenSocket, CancellationToken timeout )
    {
        using var acceptSocket = await listenSocket.AcceptAsync( timeout ).ConfigureAwait( false );
        acceptSocket.NoDelay = true; // Disable Nagle algorithm.
        var buffer = new byte[1];
        acceptSocket.Receive( buffer ).Should().Be( 1 );
        return buffer[0];
    }
}
