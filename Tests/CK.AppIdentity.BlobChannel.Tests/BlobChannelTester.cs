using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
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
        // The lists may already contain the messages of a previous check: this one checks its own.
        int senderFrom = GetCount( _senderReceived );
        int listenerFrom = GetCount( _listenerReceived );
        if( asyncSend )
        {
            await SendTestDataAsync( _listenerChannel, token );
            await SendTestDataAsync( _senderChannel, token );
        }
        else
        {
            SendTestData( _listenerChannel );
            SendTestData( _senderChannel );
        }
        await CheckTestDataReceivedAsync( _senderReceived, token, senderFrom );
        await CheckTestDataReceivedAsync( _listenerReceived, token, listenerFrom );
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
    /// <see cref="CheckSendReceiveAsync(bool, CancellationToken)"/> can be used to challenge an opened connection between them.
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
    /// Uses <see cref="CreateAndStartListenerAsync(string, NormalizedPath, Action{ServiceCollection}?, CancellationToken)"/>
    /// and <see cref="CreateAndStartSenderAsync(string, NormalizedPath, Action{ServiceCollection}?, CancellationToken)"/>
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
        }, Configure( configureServices ), token );
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
        }, Configure( configureServices ), token );
    }

    static Action<ServiceCollection> Configure( Action<ServiceCollection>? configureServices )
    {
        return services =>
        {
            services.AddSingleton<BlobChannelFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<BlobChannelFeatureDriver>() );
            configureServices?.Invoke( services );
        };
    }

    /// <summary>
    /// Starts listening to the <see cref="BlobChannelFeature.Received"/> event on the single
    /// remote of the <paramref name="from"/> side that must have the <see cref="BlobChannelFeature"/>.
    /// </summary>
    /// <param name="from">The side from which data must be received.</param>
    /// <param name="receivedData">The list to fill.</param>
    /// <returns>The BlobChannel feature.</returns>
    public static BlobChannelFeature SetupChannel( ApplicationIdentityService from, List<byte[]> receivedData )
    {
        var channel = from.Remotes.Single().GetRequiredFeature<BlobChannelFeature>();
        channel.Received.Sync += ( monitor, sender, bytes ) =>
        {
            monitor.Info( $"{sender.Transport.Party.ApplicationIdentityService}: RECEIVED {bytes.Length} bytes." );
            // This runs on the receive loop: the list is read by the test (see CheckTestDataReceivedAsync).
            lock( receivedData ) receivedData.Add( bytes );
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
        (await c.TrySendAsync( [1], token )).ShouldBeTrue();
        (await c.TrySendAsync( [1, 2], token )).ShouldBeTrue();
        (await c.TrySendAsync( [1, 2, 3], token )).ShouldBeTrue();
    }

    /// <summary>
    /// Sends 3 messages of 1, 2 and 3 bytes on the channel.
    /// The <see cref="TransportFeature.ReadyTask"/> must be completed.
    /// </summary>
    /// <param name="c">The channel.</param>
    public static void SendTestData( BlobChannelFeature c )
    {
        c.TrySend( [1] ).ShouldBeTrue();
        c.TrySend( [1, 2] ).ShouldBeTrue();
        c.TrySend( [1, 2, 3] ).ShouldBeTrue();
    }

    /// <summary>
    /// Waits for the list to contain the 3 messages that <see cref="SendTestDataAsync(BlobChannelFeature, CancellationToken)"/>
    /// or <see cref="SendTestData(BlobChannelFeature)"/> sent after the <paramref name="from"/> first ones, and checks them.
    /// <para>
    /// The list is filled by the receive loop of the channel: it must be locked (see <see cref="SetupChannel"/>).
    /// This never spins: a synchronous "while( received.Count &lt; 3 ) ;" cannot be canceled (a [CancelAfter] is
    /// cooperative) and, in Release, the Count read may be hoisted out of the loop so that it never ends.
    /// </para>
    /// </summary>
    /// <param name="received">The received messages.</param>
    /// <param name="token">The cancellation token.</param>
    /// <param name="from">The number of messages received before the 3 ones to check.</param>
    /// <returns>The awaitable.</returns>
    public static async Task CheckTestDataReceivedAsync( List<byte[]> received, CancellationToken token, int from = 0 )
    {
        await WaitUntilAsync( () => GetCount( received ) >= from + 3, token );
        byte[][] messages;
        lock( received ) messages = received.GetRange( from, 3 ).ToArray();
        messages[0].ShouldBe( [1] );
        messages[1].ShouldBe( [1, 2] );
        messages[2].ShouldBe( [1, 2, 3] );
    }

    /// <summary>
    /// Waits for a condition that another thread makes true, polling it every 10 ms until the
    /// <paramref name="token"/> is canceled (a [CancelAfter] then fails the test instead of hanging it).
    /// </summary>
    /// <param name="condition">The condition to wait for.</param>
    /// <param name="token">The cancellation token.</param>
    /// <returns>The awaitable.</returns>
    public static async Task WaitUntilAsync( Func<bool> condition, CancellationToken token )
    {
        while( !condition() )
        {
            await Task.Delay( 10, token );
        }
    }

    static int GetCount( List<byte[]> received )
    {
        lock( received ) return received.Count;
    }

}
