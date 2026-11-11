using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

[TestFixture]
public class DevRunningStatusTests
{
    const string StorePath = "TestStore/#Dev/Store";

    static async Task<ApplicationIdentityService> StartAsync( Action<MutableConfigurationSection> configuration, CancellationToken cancel )
    {
        var config = new MutableConfigurationSection( "CK-AppIdentity" );
        config["Defaults:AutoTrustKey"] = "Once";
        configuration( config );
        // The "#Dev/Store" of a development solution (a host in Development computes it from its solution).
        var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor,
                                                                config,
                                                                null,
                                                                null,
                                                                CoreApplicationIdentity.DefaultEnvironmentName,
                                                                TestHelper.TestProjectFolder,
                                                                TestHelper.TestProjectFolder.Combine( StorePath ) ).ShouldNotBeNull();
        var s = await TestHelper.CreateApplicationServiceAsync( c, services =>
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( new SystemClockTester( 50 ) );
            services.AddSingleton<DevRunningStatusFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<DevRunningStatusFeatureDriver>() );
        }, cancel );
        // Starts the static features (what a host does).
        await s.StartAndInitializeAsync().WaitAsync( cancel );
        return s;
    }

    static NormalizedPath GetStatusPath( ApplicationIdentityService s ) => s.SharedFileStore.FolderPath.AppendPart( DevRunningStatusFeatureDriver.FileName );

    // The rewrites are batched: waits until the file says what is expected.
    static async Task<JsonElement> WaitForAsync( NormalizedPath path, Func<JsonElement, bool> condition, CancellationToken cancel )
    {
        for(; ; )
        {
            // Read like the store reads it: this never prevents the party from rewriting the file.
            var bytes = StoreFileReader.TryReadAllBytes( path );
            if( bytes != null )
            {
                var e = JsonDocument.Parse( bytes ).RootElement.Clone();
                if( condition( e ) ) return e;
            }
            await Task.Delay( 100, cancel );
        }
    }

    [Test]
    [CancelAfter( 20000 )]
    public async Task the_transport_contributes_the_listeners_and_the_availability_of_the_remotes_Async( CancellationToken cancel )
    {
        TestHelper.CleanupFolder( TestHelper.TestProjectFolder.Combine( StorePath ) );
        await using var listener = await StartAsync( c =>
        {
            c["FullName"] = "Test/$DevListener";
            c["Parties:0:PartyName"] = "$DevSender";
            c["Defaults:ListeningAddress:0"] = "tcp:127.0.0.1:37128";
        }, cancel );
        var listenerStatus = await WaitForAsync( GetStatusPath( listener ), e => e.TryGetProperty( "Transport", out _ ), cancel );
        var transport = listenerStatus.GetProperty( "Transport" );
        // The description has the actual address when it differs (here, the dual mode socket: "-> [::ffff:127.0.0.1]:37128").
        transport.GetProperty( "Listeners" ).EnumerateArray().Single().GetString().ShouldStartWith( "TCP on 127.0.0.1:37128" );
        // No outgoing remote: the listener is ready at once.
        listenerStatus.GetProperty( "Ready" ).GetBoolean().ShouldBeTrue();

        await using var sender = await StartAsync( c =>
        {
            c["FullName"] = "Test/$DevSender";
            c["Parties:0:PartyName"] = "$DevListener";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37128";
        }, cancel );
        // The sender is ready once its remote is connected.
        var senderStatus = await WaitForAsync( GetStatusPath( sender ), e => e.GetProperty( "Ready" ).GetBoolean(), cancel );
        transport = senderStatus.GetProperty( "Transport" );
        transport.GetProperty( "Listeners" ).GetArrayLength().ShouldBe( 0 );
        var remote = transport.GetProperty( "Remotes" ).EnumerateArray().Single();
        remote.GetProperty( "FullName" ).GetString().ShouldBe( "Test/$DevListener/#Dev" );
        remote.GetProperty( "Availability" ).GetString().ShouldBe( "Connected" );

        // The listener sees the sender connected.
        await WaitForAsync( GetStatusPath( listener ),
                            e => e.GetProperty( "Transport" ).GetProperty( "Remotes" ).EnumerateArray()
                                  .Any( r => r.GetProperty( "FullName" ).GetString() == "Test/$DevSender/#Dev"
                                             && r.GetProperty( "Availability" ).GetString() == "Connected" ),
                            cancel );

        // When the listener stops, the sender is no more ready.
        await listener.DisposeAsync();
        senderStatus = await WaitForAsync( GetStatusPath( sender ), e => !e.GetProperty( "Ready" ).GetBoolean(), cancel );
        senderStatus.GetProperty( "Transport" ).GetProperty( "Remotes" )[0].GetProperty( "Availability" ).GetString().ShouldNotBe( "Connected" );
    }

    [Test]
    [CancelAfter( 30000 )]
    public async Task a_sender_that_waits_for_an_approval_is_ready_and_says_what_is_pending_Async( CancellationToken cancel )
    {
        TestHelper.CleanupFolder( TestHelper.TestProjectFolder.Combine( StorePath ) );
        await using var listener = await StartAsync( c =>
        {
            c["FullName"] = "Test/$DevApprover";
            c["Parties:0:PartyName"] = "$DevWaiting";
            // The listener never trusts the sender automatically: an operator must approve it.
            c["Parties:0:AutoTrustKey"] = "Never";
            c["Defaults:ListeningAddress:0"] = "tcp:127.0.0.1:37129";
        }, cancel );
        await using var sender = await StartAsync( c =>
        {
            c["FullName"] = "Test/$DevWaiting";
            c["Parties:0:PartyName"] = "$DevApprover";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37129";
        }, cancel );
        // Not connected, but ready: its approval is pending (with the approval code once the attempts exchanged it).
        var status = await WaitForAsync( GetStatusPath( sender ),
                                         e => e.GetProperty( "Transport" ).TryGetProperty( "Pending", out var p )
                                              && p.EnumerateArray().Any( m => m.GetString()!.Contains( "approval code" ) ),
                                         cancel );
        status.GetProperty( "Ready" ).GetBoolean().ShouldBeTrue();
        status.GetProperty( "Transport" ).GetProperty( "Remotes" )[0].GetProperty( "Availability" ).GetString().ShouldNotBe( "Connected" );
        status.GetProperty( "Transport" ).GetProperty( "Pending" ).EnumerateArray().Single().GetString()
              .ShouldStartWith( "'Test/$DevApprover/#Dev' must accept this party: " );
    }

    [Test]
    [CancelAfter( 20000 )]
    public async Task the_key_management_contributes_the_checkpoint_of_the_party_Async( CancellationToken cancel )
    {
        TestHelper.CleanupFolder( TestHelper.TestProjectFolder.Combine( StorePath ) );
        await using var party = await StartAsync( c => c["FullName"] = "Test/$DevCheckpoint", cancel );
        var status = await WaitForAsync( GetStatusPath( party ), e => e.TryGetProperty( "KeyManagement", out _ ), cancel );
        var checkpoint = status.GetProperty( "KeyManagement" ).GetProperty( "Checkpoints" ).EnumerateArray().Single();
        checkpoint.GetProperty( "FullName" ).GetString().ShouldBe( "Test/$DevCheckpoint/#Dev" );
        checkpoint.GetProperty( "Checkpoint" ).GetString().ShouldBe( party.GetRequiredFeature<CK.AppIdentity.KeyManagement.ILocalKeys>().Checkpoint.ToString() );
    }
}
