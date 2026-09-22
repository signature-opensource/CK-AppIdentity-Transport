using CK.AppIdentity.TransportLayer;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.MutualTls.Tests;

/// <summary>
/// Finding M0a: listener reuse used to ignore the transport type.
/// <para>
/// <c>TryEnsureListener</c> asked an existing listener <c>IsListeningAddress( endPoint.TypedAddress )</c>.
/// <c>TypedAddress</c> is declared <c>object</c>, so that bound the <c>object</c> overload and skipped
/// the public one — whose first statement, <c>if( address.Type != _transportType ) return false;</c>,
/// is the only transport-type guard on the path. Both concrete listeners then compared bare
/// <c>IPEndPoint</c> equality, which is type-blind by construction.
/// </para>
/// <para>
/// The consequence was a silent downgrade: with <c>tcp:</c> and <c>mtls:</c> on one endpoint the TCP
/// listener was created first, the <c>mtls:</c> entry matched it, and no mTLS listener was ever
/// created. An operator who explicitly asked for a secured listener got cleartext, and the only trace
/// was a <c>Trace</c> line about the listener that did get created.
/// </para>
/// </summary>
[TestFixture]
public class ListenerReuseTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureServices( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        services.AddSingleton<MutualTlsTransportTypeService>();
        services.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<MutualTlsTransportTypeService>() );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Two_transport_types_on_one_endpoint_are_refused_rather_than_silently_collapsed_Async( CancellationToken token )
    {
        // Note on what this can and cannot assert. It is tempting to want "two distinct listeners
        // exist", but that configuration cannot work: tcp: and mtls: are both TCP sockets, so the
        // second Bind on the same IPEndPoint fails whatever the code does. The defect was never that
        // the collision failed - it was that the collision was ABSORBED, turning a loud failure into a
        // cleartext listener serving an address the operator wrote as mtls:. So the property under
        // test is "this is refused", and the thing it guards against is "this comes up quietly".
        const int port = 37155;
        var ex = await Should.ThrowAsync<Exception>( async () =>
        {
            await using var s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "Test/$M0aBoth";
                c["AlwaysListening"] = "True";
                c["ListeningAddress:0"] = $"tcp:127.0.0.1:{port}";
                c["ListeningAddress:1"] = $"mtls:127.0.0.1:{port}";
                c["ListeningTypes:0"] = "tcp";
                c["ListeningTypes:1"] = "mtls";
                c["Parties:0:PartyName"] = "$M0aBothPeer";
            }, ConfigureServices, token );
        } );
        ex.ShouldNotBeNull();

        // And it must be refused for the right reason. Before the fix the mtls: entry reused the TCP
        // listener, so ObtainListeners handed the same instance back twice and AddParty ran twice for
        // one party - which in Debug trips Throw.DebugAssert( !_parties.Contains( party ) ) and
        // surfaces as a success-exception. That assert is compiled out in Release, where the same
        // configuration came up quietly with one cleartext listener. Asserting the shape of the
        // failure is what separates "refused" from "tripped over".
        ex.Message.ShouldNotContain( "HasSuccessException",
            "The collision must surface as a listener that could not be created, not as a party " +
            "added twice to a listener that should never have matched in the first place." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Each_transport_type_gets_its_own_listener_Async( CancellationToken token )
    {
        // The other half, and the one that says the guard did not simply break reuse: on two distinct
        // endpoints both listeners must be created, one of each type. Without this, "same endpoint is
        // refused" would also pass on code that refused everything.
        const int tcpPort = 37156;
        const int mtlsPort = 37157;
        await using var s = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$M0aTwo";
            c["AlwaysListening"] = "True";
            c["ListeningAddress:0"] = $"tcp:127.0.0.1:{tcpPort}";
            c["ListeningAddress:1"] = $"mtls:127.0.0.1:{mtlsPort}";
            c["ListeningTypes:0"] = "tcp";
            c["ListeningTypes:1"] = "mtls";
            c["Parties:0:PartyName"] = "$M0aTwoPeer";
        }, ConfigureServices, token );

        var feature = s.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        feature.IsListening.ShouldBeTrue();
        var names = feature.Listeners!.Select( l => l.GetType().Name ).OrderBy( n => n ).ToArray();
        names.ShouldBe( new[] { "MutualTlsListener", "TcpSocketListener" },
            "One listener per transport type: the mtls: entry must not be absorbed by the tcp: one." );
    }
}
