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
    const string StorePath = "TestStore/DevStore";

    static async Task<ApplicationIdentityService> StartAsync( Action<MutableConfigurationSection> configuration, CancellationToken cancel )
    {
        var config = new MutableConfigurationSection( "CK-AppIdentity" );
        // A relative store, resolved against the content root: the "#Dev/Store" of a development solution.
        config["StoreRootPath"] = StorePath;
        config["Defaults:AutoTrustKey"] = "Once";
        configuration( config );
        var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, config, basePath: TestHelper.TestProjectFolder ).ShouldNotBeNull();
        var s = await TestHelper.CreateApplicationServiceAsync( c, services =>
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( new SystemClockTester( 50 ) );
            services.AddSingleton<DevRunningStatusFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<DevRunningStatusFeatureDriver>() );
            services.AddSingleton<TransportDevRunningStatusContributor>();
            services.AddSingleton<IDevRunningStatusContributor>( sp => sp.GetRequiredService<TransportDevRunningStatusContributor>() );
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
            if( File.Exists( path ) )
            {
                var e = JsonDocument.Parse( File.ReadAllText( path ) ).RootElement.Clone();
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
}
