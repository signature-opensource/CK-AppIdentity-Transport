using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M6: the send hook ran more than once per message.
/// <para>
/// <see cref="PeerProtocolHandler.OnSendMessage"/> is called before the write. A write that is
/// canceled leaves the message in the queue on purpose — losing it on a dropped connection would be
/// worse — so the loop peeks it again after reconnecting and the hook runs a second time. That is
/// correct for a transform, and wrong for a side effect: CRIS used the hook to stamp the command's
/// sent date, SetSentDate is once-only by contract, and the second call threw. The throw killed the
/// transport, which reconnected, which peeked the same message — a live-lock on a poisoned queue head.
/// </para>
/// <para>
/// The fix splits the two: <see cref="PeerProtocolHandler.OnSendMessage"/> may run repeatedly and
/// must stay side-effect free, <see cref="PeerProtocolHandler.OnMessageSent"/> runs once, after the
/// bytes are out.
/// </para>
/// </summary>
[TestFixture]
public class SendHookTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureServices( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        services.AddSingleton<CountingChannelFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<CountingChannelFeatureDriver>() );
    }

    sealed class Peers : IAsyncDisposable
    {
        public required ApplicationIdentityService Listener { get; init; }
        public required ApplicationIdentityService Sender { get; init; }
        public required TransportFeature ListenerTransport { get; init; }
        public required TransportFeature SenderTransport { get; init; }
        public required CountingChannelFeature ListenerChannel { get; init; }
        public required CountingChannelFeature SenderChannel { get; init; }

        public async ValueTask DisposeAsync()
        {
            await Sender.DisposeAsync();
            await Listener.DisposeAsync();
        }
    }

    async Task<Peers> CreatePeersAsync( string name, CancellationToken token )
    {
        var listenerName = $"${name}L";
        var senderName = $"${name}S";
        var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{listenerName}";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = senderName;
        }, ConfigureServices, token: token );

        var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{senderName}";
            c["AutoTrustKey"] = "Once";
            c["AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = listenerName;
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureServices, token: token );

        var senderTransport = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var listenerTransport = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await senderTransport.ReadyTask.WaitAsync( token );
        await listenerTransport.ReadyTask.WaitAsync( token );

        return new Peers
        {
            Listener = listener,
            Sender = sender,
            ListenerTransport = listenerTransport,
            SenderTransport = senderTransport,
            ListenerChannel = listener.AllRemotes.Single().GetRequiredFeature<CountingChannelFeature>(),
            SenderChannel = sender.AllRemotes.Single().GetRequiredFeature<CountingChannelFeature>()
        };
    }

    static async Task WaitForAsync( Func<bool> condition, string what, CancellationToken token, int seconds = 30 )
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( !condition() )
        {
            if( DateTime.UtcNow > deadline ) Throw.CKException( $"Timeout while waiting for {what}." );
            await Task.Delay( 20, token );
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task OnMessageSent_is_called_once_per_message_Async( CancellationToken token )
    {
        await using var p = await CreatePeersAsync( "M6Once", token );

        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 2 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 3 ).ShouldBeTrue();

        await WaitForAsync( () => p.ListenerChannel.Received.Count == 3, "the 3 messages to arrive", token );
        p.ListenerChannel.Received.ShouldBe( [1, 2, 3] );

        for( int id = 1; id <= 3; ++id )
        {
            p.SenderChannel.AttemptCount( id ).ShouldBe( 1, $"Message {id} was offered to the hook once." );
            p.SenderChannel.SentCount( id ).ShouldBe( 1, $"Message {id} was notified sent once." );
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_skipped_message_is_never_notified_as_sent_Async( CancellationToken token )
    {
        // OnSendMessage returning false drops the message. The notification must follow the bytes,
        // not the hook: nothing was written, so nothing was sent.
        await using var p = await CreatePeersAsync( "M6Skip", token );
        p.SenderChannel.SkippedId = 2;

        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 2 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 3 ).ShouldBeTrue();

        await WaitForAsync( () => p.ListenerChannel.Received.Count == 2, "the 2 unskipped messages to arrive", token );
        p.ListenerChannel.Received.ShouldBe( [1, 3] );

        p.SenderChannel.AttemptCount( 2 ).ShouldBe( 1 );
        p.SenderChannel.SentCount( 2 ).ShouldBe( 0, "Skipped: it never reached the transport." );
        p.SenderChannel.SentCount( 1 ).ShouldBe( 1 );
        p.SenderChannel.SentCount( 3 ).ShouldBe( 1 );
    }

    [Test, CancelAfter( 120000 )]
    public async Task A_retried_send_offers_the_message_twice_but_notifies_once_Async( CancellationToken token )
    {
        // The finding itself. The message is parked inside OnSendMessage, the connection is severed
        // under it, and the write that follows is refused: the message stays queued and is offered
        // again on the next transport. Before the split this second offer was a second side effect.
        await using var p = await CreatePeersAsync( "M6Retry", token );

        var dyingTransport = p.SenderTransport.CurrentTransport;
        dyingTransport.ShouldNotBeNull();

        p.SenderChannel.GatedId = 1;
        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();

        // The send loop is now inside OnSendMessage, past the condemned-transport check and before
        // the write. This is the only window where a message can be offered and then not sent.
        p.SenderChannel.GateEntered.Wait( 30_000, token ).ShouldBeTrue( "The gated message reached OnSendMessage." );
        p.SenderChannel.AttemptCount( 1 ).ShouldBe( 1 );

        // Sever the connection from the LISTENER side. Switching the sender off instead would close
        // its controller, which drains the queue: the message would be released, not retried.
        p.ListenerTransport.SwitchOff( "M6: severing the connection under a parked send." );
        await WaitForAsync( () => dyingTransport!.Lifetime.IsCancellationRequested,
                            "the sender's transport to die", token );

        p.SenderChannel.SentCount( 1 ).ShouldBe( 0, "Still parked: nothing has been written yet." );

        // Release it: the write is refused on the dead lifetime and the message stays in the queue.
        p.SenderChannel.SendGate.Set();

        p.ListenerTransport.SwitchOn();
        await WaitForAsync( () => p.ListenerChannel.Received.Count == 1,
                            "the message to arrive over the new connection", token, 90 );
        p.ListenerChannel.Received.ShouldBe( [1] );

        p.SenderChannel.AttemptCount( 1 ).ShouldBeGreaterThanOrEqualTo( 2,
            "The message was offered to OnSendMessage again after the reconnection: that is why the " +
            "hook must be side effect free." );
        p.SenderChannel.SentCount( 1 ).ShouldBe( 1,
            "But it was sent exactly once. OnMessageSent is where a once-only side effect belongs." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_throwing_OnMessageSent_does_not_resend_the_message_Async( CancellationToken token )
    {
        // The message is already gone when the notification runs, so a handler that throws must not
        // be able to push the loop into resending it — nor to kill the transport.
        await using var p = await CreatePeersAsync( "M6Throw", token );
        p.SenderChannel.ThrowOnMessageSent = true;

        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 2 ).ShouldBeTrue();

        await WaitForAsync( () => p.ListenerChannel.Received.Count == 2, "both messages to arrive", token );
        p.ListenerChannel.Received.ShouldBe( [1, 2] );
        p.SenderChannel.AttemptCount( 1 ).ShouldBe( 1, "The throw did not cause a resend." );
        p.SenderChannel.SentCount( 1 ).ShouldBe( 1 );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_throwing_OnSendMessage_drops_the_message_without_killing_the_transport_Async( CancellationToken token )
    {
        // Escaping the send loop kills the transport, which reconnects and peeks the same message:
        // it throws again, forever. The message must be dropped instead.
        await using var p = await CreatePeersAsync( "M6ThrowSend", token );
        var transport = p.SenderTransport.CurrentTransport;
        transport.ShouldNotBeNull();
        p.SenderChannel.ThrowOnSendId = 2;

        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 2 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 3 ).ShouldBeTrue();

        await WaitForAsync( () => p.ListenerChannel.Received.Count == 2, "the 2 other messages to arrive", token );
        p.ListenerChannel.Received.ShouldBe( [1, 3] );

        p.SenderChannel.AttemptCount( 2 ).ShouldBe( 1, "Dropped, not retried." );
        p.SenderChannel.SentCount( 2 ).ShouldBe( 0 );
        transport.Lifetime.IsCancellationRequested.ShouldBeFalse( "The transport survived." );
        p.SenderTransport.CurrentTransport.ShouldBeSameAs( transport );
    }
}
