using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Two real parties rotating: each side must follow the other's committed rotation through a plain
/// reconnection, with no operator and no AutoTrustKey involved after the first contact.
/// </summary>
[TestFixture]
public class RotationWireTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    const string Listener = "$RotL";
    const string Sender = "$RotS";

    Task<ApplicationIdentityService> CreateListenerAsync( CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{Listener}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = Sender;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );

    Task<ApplicationIdentityService> CreateSenderAsync( CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{Sender}";
            c["Parties:0:PartyName"] = Listener;
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{AdversarialPeer.DefaultListenerPort}";
            c["Parties:0:AutoTrustKey"] = "Once";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );

    static Task ReadyAsync( ApplicationIdentityService s, CancellationToken token )
        => s.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );

    static IRemoteKeys RemoteKeys( ApplicationIdentityService s ) => s.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>();

    [Test, CancelAfter( 60000 )]
    public async Task Both_sides_follow_a_rotation_through_a_reconnection_Async( CancellationToken token )
    {
        PeerStore.ClearRemoteTrust( $"Test/{Listener}" );
        PeerStore.ClearRemoteTrust( $"Test/{Sender}" );

        // First contact: each pins the other's inception.
        await using( var l = await CreateListenerAsync( token ) )
        await using( var s = await CreateSenderAsync( token ) )
        {
            await ReadyAsync( s, token );
            await ReadyAsync( l, token );
            RemoteKeys( l ).TrustedEvent!.Seq.ShouldBe( 0 );
            RemoteKeys( s ).TrustedEvent!.Seq.ShouldBe( 0 );

            // Both rotate while connected. Nothing is presented until the next handshake.
            s.GetRequiredFeature<ILocalKeys>().Rotate( TestHelper.Monitor ).ShouldBeTrue();
            l.GetRequiredFeature<ILocalKeys>().Rotate( TestHelper.Monitor ).ShouldBeTrue();
        }

        // Next contact: the sender's tail reaches the listener in the InitialMessage, the listener's
        // reaches the sender in the AcceptedProtocols. Both pins move, and the connection comes up.
        await using( var l = await CreateListenerAsync( token ) )
        await using( var s = await CreateSenderAsync( token ) )
        {
            await ReadyAsync( s, token );
            await ReadyAsync( l, token );
            RemoteKeys( l ).TrustedEvent!.Seq.ShouldBe( 1, "The listener followed the sender's rotation." );
            RemoteKeys( s ).TrustedEvent!.Seq.ShouldBe( 1, "The sender followed the listener's rotation." );
            l.GetRequiredFeature<ILocalKeys>().Alerts.ShouldBeEmpty();
            s.GetRequiredFeature<ILocalKeys>().Alerts.ShouldBeEmpty();
        }
    }
}
