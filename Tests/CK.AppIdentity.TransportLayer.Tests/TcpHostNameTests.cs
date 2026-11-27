using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

[TestFixture]
public class TcpHostNameTests
{
    static string Section() => "Parties:0:Address";

    [TestCase( "127.0.0.1:3712", "127.0.0.1:3712" )]
    [TestCase( "[::1]:3712", "[::1]:3712" )]
    [TestCase( "127.0.0.1", "127.0.0.1:37120" )]
    [TestCase( "auth3.sample.example.com:37300", "dns auth3.sample.example.com:37300" )]
    [TestCase( "localhost", "dns localhost:37120" )]
    [TestCase( "auth3", "dns auth3:37120" )]
    public void an_address_is_an_IP_address_or_a_host_name( string typed, string expected )
    {
        var a = new TcpSocketTransportTypeService().ParseAddress( TestHelper.Monitor, typed, Section() ).ShouldNotBeNull();
        var described = a.TypedAddress switch
        {
            DnsEndPoint d => $"dns {d.Host}:{d.Port}",
            IPEndPoint ip => ip.ToString(),
            _ => "?"
        };
        described.ShouldBe( expected );
    }

    [TestCase( "bad host:3712" )]
    [TestCase( "auth3.example.com:notaport" )]
    [TestCase( "auth3.example.com:70000" )]
    [TestCase( "" )]
    public void an_invalid_address_is_an_error( string typed )
    {
        using( TestHelper.Monitor.CollectTexts( out var texts ) )
        {
            new TcpSocketTransportTypeService().ParseAddress( TestHelper.Monitor, typed, Section() ).ShouldBeNull();
            texts.ShouldContain( t => t.Contains( "It must be an IP address or a host name" ) );
        }
    }

    [Test, CancelAfter( 7000 )]
    public async Task a_remote_is_reached_by_its_host_name_Async( CancellationToken token )
    {
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$NamedListener";
            c["Defaults:KeyManagement:AutoTrustKey"] = "Once";
            c["Defaults:Transport:AlwaysListening"] = "True";
            // In the "Defaults": the local party and its remotes listen there.
            c["Defaults:Transport:ListeningAddress:tcp"] = "127.0.0.1:37130";
            c["Parties:0:PartyName"] = "$NamedSender";
        }, token: token );
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$NamedSender";
            c["Defaults:KeyManagement:AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = "$NamedListener";
            // Resolved when connecting: "localhost" may give ::1 first, every address is tried.
            c["Parties:0:Address"] = "tcp:localhost:37130";
        }, token: token );

        var senderTransport = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var listenerTransport = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await senderTransport.ReadyTask.WaitAsync( token );
        await listenerTransport.ReadyTask.WaitAsync( token );
        senderTransport.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
        listenerTransport.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
    }

    [Test, CancelAfter( 7000 )]
    public async Task a_listening_address_is_not_a_host_name_Async( CancellationToken token )
    {
        // The error is logged by the agent of the service (not by the test monitor).
        using var logCollector = CK.Monitoring.GrandOutput.Default!.CreateMemoryCollector( 1000 );
        // The party doesn't start.
        await Should.ThrowAsync<CKException>( () => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$NamedOnly";
            c["Local:Transport:AlwaysListening"] = "True";
            c["Local:Transport:ListeningAddress:tcp"] = "localhost:37131";
        }, token: token ) );
        logCollector.ExtractCurrentTexts().ShouldContain( t => t.Contains( "a listening address is an IP address" ) );
    }
}
