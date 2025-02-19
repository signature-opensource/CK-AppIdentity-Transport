using CK.AppIdentity.TransportLayer;
using CK.Core;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests;


/// <summary>
/// Helper that can start 2 <see cref="ApplicationIdentityService"/>: one with a listener and the other one with a sender
/// bound to each other so they can send/receive bytes from each other.
/// </summary>
public sealed class BlobChannelTester : IAsyncDisposable
{
    readonly List<byte[]> _listenerReceived;
    readonly List<byte[]> _senderReceived;
    readonly ApplicationIdentityService _sender;
    readonly ApplicationIdentityService _listener;
    readonly TransportManagerFeature _senderTransport;
    readonly TransportManagerFeature _listenerTransport;
    readonly BlobChannelFeature _senderChannel;
    readonly BlobChannelFeature _listenerChannel;

    public TransportManagerFeature SenderTransport => _senderTransport;

    public ApplicationIdentityService.ISystemClock SenderClock => (ApplicationIdentityService.ISystemClock)_sender.SystemClock;

    public BlobChannelFeature SenderChannel => _senderChannel;

    public TransportManagerFeature ListenerTransport => _listenerTransport;

    public ApplicationIdentityService.ISystemClock ListenerClock => (ApplicationIdentityService.ISystemClock)_listener.SystemClock;

    public BlobChannelFeature ListenerChannel => _listenerChannel;

    /// <summary>
    /// Checks that both sender and listener parties can send and receive bytes.
    /// </summary>
    /// <param name="asyncSend">
    /// Whether to use <see cref="BlobChannelFeature.TrySendAsync(byte[])"/>
    /// or <see cref="BlobChannelFeature.TrySend(byte[])"/>.
    /// </param>
    /// <returns>The awaitable.</returns>
    public async Task CheckSendReceiveAsync( bool asyncSend, CancellationToken token = default )
    {
        await _listenerChannel.Transport.ReadyTask.WaitAsync( token ).ConfigureAwait( false );
        await _senderChannel.Transport.ReadyTask.WaitAsync( token ).ConfigureAwait( false );
        if( asyncSend )
        {
            await SendTestDataAsync( _listenerChannel, token );
            await SendTestDataAsync( _senderChannel, token );
        }
        else
        {

        }

        CheckTestDataReceived( _senderReceived );
        CheckTestDataReceived( _listenerReceived );
    }

    /// <summary>
    /// Dispose the sender and listener.
    /// </summary>
    /// <returns></returns>
    public async ValueTask DisposeAsync()
    {
        await _sender.DisposeAsync();
        await _listener.DisposeAsync();
    }

    /// <summary>
    /// Initializes a new tester bound to 2 sides that must be correctly configured with a
    /// single remote bound to each other with the BlobChannel feature allowed.
    /// <see cref="CheckSendReceiveAsync(bool)"/> can be used to challenge an opened connection between them.
    /// Note that disposing the tester will dispose both sides.
    /// </summary>
    /// <param name="sender">The "sender" side (can be any of the two).</param>
    /// <param name="listener">The "listener" side (the other one).</param>
    public BlobChannelTester( ApplicationIdentityService sender, ApplicationIdentityService listener )
    {
        _listenerReceived = new List<byte[]>();
        _senderReceived = new List<byte[]>();
        _sender = sender;
        _listener = listener;
        _senderTransport = sender.GetRequiredFeature<TransportManagerFeature>();
        _listenerTransport = listener.GetRequiredFeature<TransportManagerFeature>();
        _senderChannel = SetupChannel( sender, _senderReceived );
        _listenerChannel = SetupChannel( listener, _listenerReceived );
    }

    /// <summary>
    /// Uses <see cref="CreateAndStartListenerAsync(string, NormalizedPath, Action{ServiceCollection}?)"/>
    /// and <see cref="CreateAndStartSenderAsync(string, NormalizedPath, Action{ServiceCollection}?)"/>
    /// to create a <see cref="BlobChannelTester"/> on the two <see cref="ApplicationIdentityService"/>.
    /// </summary>
    /// <param name="autoTrustKey">The AutoTrustKey configuration to use (same on both side).</param>
    /// <param name="heartbeatPeriod">The <see cref="ApplicationIdentityService.ISystemClock.HeatBeatPeriod"/> to use (same on both side).</param>
    /// <param name="senderOffset">Optional clock offset to configure on the sender side (uses the <see cref="SystemClockTester"/>).</param>
    /// <param name="listenerOffset">Optional clock offset to configure on the listener side (uses the <see cref="SystemClockTester"/>).</param>
    /// <param name="storeSubPath">Optional file store sub path.</param>
    /// <returns>A running <see cref="BlobChannelTester"/>.</returns>
    public static async Task<BlobChannelTester> CreateTesterAsync( string autoTrustKey = "Never",
                                                                   int heartbeatPeriod = 0,
                                                                   TimeSpan? senderOffset = null,
                                                                   TimeSpan? listenerOffset = null,
                                                                   NormalizedPath storeSubPath = default )
    {
        var sC = new SystemClockTester( heartbeatPeriod );
        if( senderOffset.HasValue ) sC.Offset = senderOffset.Value;
        var s = await CreateAndStartSenderAsync( autoTrustKey, storeSubPath, services => services.AddSingleton( sC ) );

        var lC = new SystemClockTester( heartbeatPeriod );
        if( listenerOffset.HasValue ) lC.Offset = listenerOffset.Value;
        var l = await CreateAndStartListenerAsync( autoTrustKey, storeSubPath, services => services.AddSingleton( lC ) );

        return new BlobChannelTester( s, l );
    }

    /// <summary>
    /// Creates a "Test/$Sender" <see cref="ApplicationIdentityService"/> with a remote party "Test/$Listener"
    /// that targets the Address = "tcp:127.0.0.1". This will use the default 37120 port.
    /// AllowFeatures = "BlobChannel" is obviously specified.
    /// </summary>
    /// <param name="autoTrustKey">The AutoTrustKey configuration to use.</param>
    /// <param name="storeSubPath">Optional file store sub path.</param>
    /// <param name="configureServices">Optional services configurator.</param>
    /// <param name="token">Optional cancellation token.</param>
    /// <returns></returns>
    public static async Task<ApplicationIdentityService> CreateAndStartSenderAsync( string autoTrustKey = "Never",
                                                                                    NormalizedPath storeSubPath = default,
                                                                                    Action<ServiceCollection>? configureServices = null,
                                                                                    CancellationToken token = default )
    {
        return await TestHelper.CreateApplicationServiceAsync( c =>
        {
            if( !storeSubPath.IsEmptyPath ) c["RootStorePath"] = TestHelper.TestProjectFolder.Combine( storeSubPath );
            c["AutoTrustKey"] = autoTrustKey;
            c["FullName"] = "Test/$Sender";
            c["Parties:0:PartyName"] = "$Listener";
            c["Parties:0:Address"] = "tcp:127.0.0.1";
            c["AllowFeatures"] = "BlobChannel";
        }, configureServices, token );
    }

    /// <summary>
    /// Creates a "Test/$Listener" <see cref="ApplicationIdentityService"/> with a remote party "Test/$Sender".
    /// This uses the default configuration: the TCP listener will listen to "127.0.0.1:37120".
    /// AllowFeatures = "BlobChannel" is obviously specified.
    /// </summary>
    /// <param name="autoTrustKey">The AutoTrustKey configuration to use.</param>
    /// <param name="storeSubPath">Optional file store sub path.</param>
    /// <param name="configureServices">Optional services configurator.</param>
    /// <param name="token">Optional cancellation token.</param>
    /// <returns></returns>
    public static async Task<ApplicationIdentityService> CreateAndStartListenerAsync( string autoTrustKey = "Never",
                                                                                      NormalizedPath storeSubPath = default,
                                                                                      Action<ServiceCollection>? configureServices = null,
                                                                                      CancellationToken token = default )
    {
        return await TestHelper.CreateApplicationServiceAsync( c =>
        {
            if( !storeSubPath.IsEmptyPath ) c["RootStorePath"] = TestHelper.TestProjectFolder.Combine( storeSubPath );
            c["AutoTrustKey"] = autoTrustKey;
            c["FullName"] = "Test/$Listener";
            c["Parties:0:PartyName"] = "$Sender";
            c["AllowFeatures"] = "BlobChannel";
        }, configureServices, token );
    }

    /// <summary>
    /// Starts listening to the <see cref="BlobChannelFeature.Received"/> event on the single
    /// remote of the <paramref name="from"/> side that must have the <see cref="BlobChannelFeature"/>.
    /// </summary>
    /// <param name="from">The side from wich data must be received.</param>
    /// <param name="receivedData">The list to fill.</param>
    /// <returns>The BlobChannel feature.</returns>
    public static BlobChannelFeature SetupChannel( ApplicationIdentityService from, List<byte[]> receivedData )
    {
        var channel = from.Remotes.Single().GetRequiredFeature<BlobChannelFeature>();
        channel.Received.Sync += ( monitor, sender, bytes ) =>
        {
            monitor.Info( $"{sender.Transport.Party.ApplicationIdentityService}: RECEIVED {bytes.Length} bytes." );
            receivedData.Add( bytes );
        };
        return channel;
    }

    /// <summary>
    /// Sends 3 messages of 1, 2 and 3 bytes on the channel.
    /// This awaits the <see cref="TransportFeature.ReadyTask"/> (unlike <see cref="SendTestData(BlobChannelFeature)"/>).
    /// </summary>
    /// <param name="c">The channel.</param>
    /// <param name="token">Optional cancellation token.</param>
    /// <returns>The awaitable.</returns>
    public static async Task SendTestDataAsync( BlobChannelFeature c, CancellationToken token = default )
    {
        await c.Transport.ReadyTask;
        (await c.TrySendAsync( new byte[] { 1 }, token )).Should().BeTrue();
        (await c.TrySendAsync( new byte[] { 1, 2 }, token )).Should().BeTrue();
        (await c.TrySendAsync( new byte[] { 1, 2, 3 }, token )).Should().BeTrue();
    }

    /// <summary>
    /// Sends 3 messages of 1, 2 and 3 bytes on the channel.
    /// The <see cref="TransportFeature.ReadyTask"/> must be completed.
    /// </summary>
    /// <param name="c">The channel.</param>
    public static void SendTestData( BlobChannelFeature c )
    {
        c.TrySend( new byte[] { 1 } ).Should().BeTrue();
        c.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
        c.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();
    }

    /// <summary>
    /// Waits for the list to contain at least 3 messages (by a rather stupid polling)
    /// and then check their content: they must be the same as the <see cref="SendTestDataAsync(BlobChannelFeature)"/> sent.
    /// </summary>
    /// <param name="received"></param>
    public static void CheckTestDataReceived( List<byte[]> received )
    {
        while( received.Count < 3 ) ;
        received[0].Should().BeEquivalentTo( new byte[] { 1 } );
        received[1].Should().BeEquivalentTo( new byte[] { 1, 2 } );
        received[2].Should().BeEquivalentTo( new byte[] { 1, 2, 3 } );
    }

}
