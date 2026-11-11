using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.IO.AuthCenter;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.AuthCenter.Tests;

/// <summary>
/// The System list signed by the Authentication Center (the "$Listener" of the pair), and kept by its remote.
/// </summary>
[TestFixture]
public class SystemListTests
{
    static readonly Type[] _types = [typeof( IRevokePartyCommand ), typeof( ISystemListCommand ), typeof( IGetSystemListQCommand ), typeof( SystemListHandler )];

    static Task<int?> RevokeAsync( RemoteAuthCenterTests.Pair p, string fullName, byte[] identity )
    {
        var command = p.Center.PocoDirectory.Create<IRevokePartyCommand>( r =>
        {
            r.PartyFullName = fullName;
            r.Identity = identity;
        } );
        return new RevokePartyHandler().HandleAsync( TestHelper.Monitor, command, new CurrentLocalParty( p.Center.ApplicationIdentityService ) );
    }

    static byte[] Identity( int i )
    {
        var identity = new byte[KeyEvent.HashSize];
        identity[0] = (byte)i;
        identity[1] = 42;
        return identity;
    }

    [Test]
    public async Task concurrent_updates_lose_nothing_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: _types );
        var list = p.Center.ApplicationIdentityService.GetRequiredFeature<AuthCenterSystemList>();
        const int count = 20;
        var seqs = await Task.WhenAll( Enumerable.Range( 0, count )
                                                 .Select( i => Task.Run( () => RevokeAsync( p, $"Test/$Ghost{i}/#Dev", Identity( i ) ) ) ) );
        seqs.ShouldAllBe( s => s != null );
        seqs.Distinct().Count().ShouldBe( count, "Each revocation signs its own list." );
        var current = list.Current.ShouldNotBeNull();
        for( int i = 0; i < count; ++i )
        {
            current.Entries.ShouldContain( e => e.FullName == $"Test/$Ghost{i}/#Dev", "No revocation is lost." );
        }
        // Each returned list contains its revocation (the update of a list sees the previous one).
        current.Seq.ShouldBe( seqs.Max()!.Value );
    }

    [Test]
    public async Task a_revoked_party_is_no_more_a_route_host_even_when_configured_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: _types,
                                                                    centerSettings: c => c["Local:AuthCenter:RouteHosts:MailSender"] = "Test/$Mail1/#Dev" );
        var list = p.Center.ApplicationIdentityService.GetRequiredFeature<AuthCenterSystemList>();
        for( int i = 0; i < 100 && list.RouteHosts.Find( "MailSender", "Test/$Mail1/#Dev" ) == null; ++i ) await Task.Delay( 100 );
        list.RouteHosts.Find( "MailSender", "Test/$Mail1/#Dev" ).ShouldNotBeNull( "The configured host is authorized." );

        (await RevokeAsync( p, "Test/$Mail1/#Dev", Identity( 1 ) )).ShouldNotBeNull();
        list.Current.ShouldNotBeNull().RouteHosts.ShouldNotContain( h => h.Host == "Test/$Mail1/#Dev" );

        // Any update (the synchronization of the configured hosts, an authorization) can't add it back.
        await list.UpdateAsync( TestHelper.Monitor, ( entries, hosts ) => (entries, [.. hosts, new RouteHost( "MailSender", "Test/$Mail1/#Dev", null )]) );
        (await list.AuthorizeAsync( TestHelper.Monitor, "Test/$Mail1/#Dev", ["Other"] )).ShouldNotBeNull();
        list.Current.ShouldNotBeNull().RouteHosts.ShouldNotContain( h => h.Host == "Test/$Mail1/#Dev" );
        list.RouteHosts.Find( "MailSender", "Test/$Mail1/#Dev" ).ShouldBeNull();
    }
}
