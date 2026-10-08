using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
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
/// R1: a connection that stays up never renegotiates. The new key events of a party are pushed to its connected
/// remotes right after a rotation, and a remote can ask for them.
/// </summary>
[TestFixture]
public class KeyEventsPushTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    async Task<(ApplicationIdentityService Listener, ApplicationIdentityService Sender)> StartAsync( string prefix, CancellationToken token )
    {
        PeerStore.ClearLocalParty( $"Test/${prefix}Listener" );
        PeerStore.ClearLocalParty( $"Test/${prefix}Sender" );
        PeerStore.ClearRemoteTrust( $"Test/${prefix}Listener" );
        PeerStore.ClearRemoteTrust( $"Test/${prefix}Sender" );
        var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${prefix}Listener";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = $"${prefix}Sender";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );
        var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${prefix}Sender";
            c["AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = $"${prefix}Listener";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );
        await sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
        await listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
        return (listener, sender);
    }

    static async Task<bool> WaitForAsync( Func<bool> condition, CancellationToken token )
    {
        for( int i = 0; i < 100; ++i )
        {
            if( condition() ) return true;
            await Task.Delay( 50, token );
        }
        return condition();
    }

    [Test, CancelAfter( 20000 )]
    public async Task a_rotation_is_pushed_to_the_connected_remotes_Async( CancellationToken token )
    {
        var (listener, sender) = await StartAsync( "Push", token );
        await using var _ = listener;
        await using var __ = sender;
        var senderKeys = sender.GetRequiredFeature<ILocalKeys>();
        var senderOnListener = listener.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>();
        senderOnListener.TrustedEvent.ShouldNotBeNull().Seq.ShouldBe( senderKeys.Seq );
        var signature = senderKeys.Sign( "Test.Purpose", "data"u8, DateTime.UtcNow.AddHours( 1 ) );
        senderOnListener.Verify( TestHelper.Monitor, "Test.Purpose", "data"u8, signature ).ShouldBeTrue();

        // The sender rotates: the connection stays up, the listener moves its pin from the pushed events.
        senderKeys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        var rotated = senderKeys.Sign( "Test.Purpose", "data"u8, DateTime.UtcNow.AddHours( 1 ) );
        (await WaitForAsync( () => senderOnListener.TrustedEvent?.Seq == senderKeys.Seq, token )).ShouldBeTrue( "The pin moved without a handshake." );
        senderOnListener.Check( TestHelper.Monitor, "Test.Purpose", "data"u8, rotated ).ShouldBe( SignatureVerdict.Valid );
        senderOnListener.Verify( TestHelper.Monitor, "Test.Purpose", "data"u8, signature ).ShouldBeTrue( "What the previous key signed stays valid." );
        listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
    }

    [Test, CancelAfter( 20000 )]
    public async Task a_remote_can_ask_for_the_key_events_Async( CancellationToken token )
    {
        var (listener, sender) = await StartAsync( "Request", token );
        await using var _ = listener;
        await using var __ = sender;
        var senderOnListener = listener.AllRemotes.Single();
        var transport = senderOnListener.GetRequiredFeature<TransportFeature>();

        // Nothing new: the events are received but the pin doesn't move.
        (await transport.RequestKeyEventsAsync( TimeSpan.FromSeconds( 5 ) )).ShouldBeFalse();

        // Before the sender's heartbeat pushes them, the listener asks for them.
        var senderKeys = sender.GetRequiredFeature<ILocalKeys>();
        senderKeys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        await transport.RequestKeyEventsAsync( TimeSpan.FromSeconds( 5 ) );
        (await WaitForAsync( () => senderOnListener.GetRequiredFeature<IRemoteKeys>().TrustedEvent?.Seq == senderKeys.Seq, token )).ShouldBeTrue();
    }
}
