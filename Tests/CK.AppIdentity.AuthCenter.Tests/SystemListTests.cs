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
    public async Task a_stored_list_that_the_AuthCenter_did_not_sign_is_not_applied_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: _types );
        (await RevokeAsync( p, "Test/$Ghost/#Dev", Identity( 200 ) )).ShouldNotBeNull();
        var centerList = p.Center.ApplicationIdentityService.GetRequiredFeature<AuthCenterSystemList>().Current.ShouldNotBeNull();
        var remote = p.Remote.ApplicationIdentityService;
        var center = remote.GetRequiredFeature<CrisAuthCenter>();
        // Once the remote holds the list, it knows the keys of the AuthCenter.
        var held = remote.GetRequiredFeature<AuthCenterSystemList>();
        for( int i = 0; i < 100 && held.Current?.Seq != centerList.Seq; ++i ) await Task.Delay( 100 );
        held.Current.ShouldNotBeNull().Seq.ShouldBe( centerList.Seq );

        // The list of the AuthCenter, read from the store: verified and applied.
        var loaded = await AuthCenterSystemList.CreateAsync( TestHelper.Monitor, center, null, null, centerList.Encode() );
        loaded.Current.ShouldNotBeNull().Seq.ShouldBe( centerList.Seq );

        // A stored list that its AuthCenter didn't sign, with a greater sequence number (the AuthCenter has been replaced
        // or re-incepted; here the remote signs it): not applied, it doesn't block the lists of the AuthCenter.
        var forged = SystemList.Create( remote.GetRequiredFeature<ILocalKeys>(), centerList.Seq + 40, [], [new RouteHost( "MailSender", "Test/$Evil/#Dev", null )], DateTime.UtcNow );
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            var ignored = await AuthCenterSystemList.CreateAsync( TestHelper.Monitor, center, null, null, forged.Encode() );
            ignored.Current.ShouldBeNull();
            ignored.RouteHosts.Find( "MailSender", "Test/$Evil/#Dev" ).ShouldBeNull();
            logs.ShouldContain( l => l.Contains( $"stored by '{remote}' is signed by a key of the AuthCenter '{center.AuthCenterFullName}' that is not known yet" ) );
            // Verified with the key events of the AuthCenter (by the first heartbeat): still refused.
            (await ignored.TryAdoptAsync( TestHelper.Monitor, forged.Encode(), null )).ShouldBeFalse();
            (await ignored.TryAdoptAsync( TestHelper.Monitor, centerList.Encode(), null )).ShouldBeTrue();
        }
    }

    [Test]
    public async Task a_failed_pull_is_retried_after_the_retry_period_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: _types );
        (await RevokeAsync( p, "Test/$GhostPull/#Dev", Identity( 201 ) )).ShouldNotBeNull();
        var centerList = p.Center.ApplicationIdentityService.GetRequiredFeature<AuthCenterSystemList>().Current.ShouldNotBeNull();
        var center = p.Remote.ApplicationIdentityService.GetRequiredFeature<CrisAuthCenter>();
        // Once the remote holds the list, it knows the keys of the AuthCenter.
        var held = p.Remote.ApplicationIdentityService.GetRequiredFeature<AuthCenterSystemList>();
        for( int i = 0; i < 100 && held.Current?.Seq != centerList.Seq; ++i ) await Task.Delay( 100 );
        bool fail = true;
        var list = await AuthCenterSystemList.CreateAsync( TestHelper.Monitor, center,
                                                           _ => fail ? throw new Exception( "No answer." ) : Task.FromResult<object?>( centerList.Encode() ),
                                                           null, null );
        await list.PullOrRenewAsync( TestHelper.Monitor );
        list.NextPull.ShouldBeLessThanOrEqualTo( center.UtcNow + AuthCenterSystemList.RetryPeriod, "A failed pull is retried soon, not in an hour." );

        fail = false;
        await list.PullOrRenewAsync( TestHelper.Monitor );
        list.Current.ShouldNotBeNull().Seq.ShouldBe( centerList.Seq );
        list.NextPull.ShouldBeGreaterThan( center.UtcNow + AuthCenterSystemList.RetryPeriod );
        // Nothing newer: obtained all the same.
        await list.PullOrRenewAsync( TestHelper.Monitor );
        list.NextPull.ShouldBeGreaterThan( center.UtcNow + AuthCenterSystemList.RetryPeriod );
    }

    [Test]
    public async Task decoding_allocates_nothing_from_an_announced_count_or_length_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: _types );
        var list = SystemList.Create( p.Center.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>(), 1, [], [], DateTime.UtcNow );
        var encoded = list.Encode();
        // The count of revocations (after the length, the version, the sequence number and the time) announces the maximum.
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian( encoded.AsSpan( 4 + 1 + 4 + 8 ), SystemList.MaxEntryCount );
        long before = GC.GetAllocatedBytesForCurrentThread();
        SystemList.TryDecode( encoded, out _ ).ShouldBeFalse();
        (GC.GetAllocatedBytesForCurrentThread() - before).ShouldBeLessThan( 100_000 );

        // A decrypted routed command that announces a 2 GB command.
        var m = new System.IO.MemoryStream();
        using( var w = new System.IO.BinaryWriter( m, System.Text.Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( "token" );
            w.Write7BitEncodedInt( 0 );
            w.Write7BitEncodedInt( 0x7FFFFFC0 );
            w.Write( (byte)1 );
        }
        var plain = m.ToArray();
        before = GC.GetAllocatedBytesForCurrentThread();
        AuthCenterRoutedCommandSeal.TryUnpack( plain, out _, out _, out _ ).ShouldBeFalse();
        (GC.GetAllocatedBytesForCurrentThread() - before).ShouldBeLessThan( 100_000 );
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
