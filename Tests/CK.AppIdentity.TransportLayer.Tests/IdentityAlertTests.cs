using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// <see cref="IdentityAlert"/> (DESIGN-key-pre-rotation §8, "Alerts"): what raises them, that they stay
/// until acknowledged, that they are deduplicated by reporter, and that every log line carries the tag.
/// </summary>
[TestFixture]
public class IdentityAlertTests
{
    // A fast heartbeat: the event is raised from it.
    static SystemClockTester FastClock() => new SystemClockTester( 50 );

    static NormalizedPath AlertsFolder( string partyName ) => IdentityStoreHelper.GetKeysFolder( partyName ).AppendPart( "Alerts" );

    [Test, CancelAfter( 30000 )]
    public async Task A_lost_next_key_raises_an_alert_that_stays_until_acknowledged_Async( CancellationToken token )
    {
        const string partyName = "AlertNextLost";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( await IdentityStoreHelper.CreateAsync( partyName, protector, token ) ) { }
        File.Delete( IdentityStoreHelper.GetCoreKeysFolder( partyName ).AppendPart( "1.key" ) );

        // Detected at start.
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var a = s.GetRequiredFeature<ILocalKeys>().Alerts.ShouldHaveSingleItem();
            a.Kind.ShouldBe( IdentityAlertKind.NextKeyLost );
            a.IsAboutSelf.ShouldBeTrue();
            a.Seq.ShouldBe( 1 );
            a.ReportedBy.ShouldBeEmpty();
        }
        Directory.EnumerateFiles( AlertsFolder( partyName ), "*.alert" ).Count().ShouldBe( 1, "Persisted." );

        // A restart neither clears it nor duplicates it: detected again, it is a repetition.
        string id;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            var a = keys.Alerts.ShouldHaveSingleItem();
            a.Count.ShouldBe( 2 );
            id = a.Id;

            keys.Acknowledge( TestHelper.Monitor, a ).ShouldBeTrue();
            keys.Alerts.ShouldBeEmpty();
            keys.Acknowledge( TestHelper.Monitor, a ).ShouldBeFalse( "Already acknowledged." );
        }
        File.Exists( AlertsFolder( partyName ).AppendPart( id + ".alert" ) ).ShouldBeFalse( "Acknowledged: its file is in the '$TrashBin'." );

        // Acknowledging does not fix anything: the key is still missing, so the next start raises it anew.
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var a = s.GetRequiredFeature<ILocalKeys>().Alerts.ShouldHaveSingleItem();
            a.Id.ShouldBe( id, "Same fact, same identifier." );
            a.Count.ShouldBe( 1, "But a new alert." );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_failing_scheduled_rotation_raises_an_alert_and_the_party_keeps_working_Async( CancellationToken token )
    {
        const string partyName = "AlertRotationFailing";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            using var key = IdentityStoreHelper.OpenKey( s, protector, 0 );
            IdentityStoreHelper.WriteCurrentCertificate( partyName, key, DateTime.UtcNow.AddDays( 10 ) );
        }
        File.Delete( IdentityStoreHelper.GetCoreKeysFolder( partyName ).AppendPart( "1.key" ) );

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Seq.ShouldBe( 0 );
            keys.Alerts.Select( a => a.Kind ).ShouldBe( new[] { IdentityAlertKind.NextKeyLost, IdentityAlertKind.RotationFailing }, ignoreOrder: true );
            keys.CurrentIdentity.NotAfter.ShouldBeGreaterThan( DateTime.UtcNow.AddDays( 100 ),
                "The certificate is renewed for the same key so that the party keeps working." );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_pin_statement_is_judged_against_the_own_log_Async( CancellationToken token )
    {
        const string partyName = "AlertStatement";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, FastClock() );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        var fullName = IdentityStoreHelper.FullName( partyName );
        var e0 = keys.EventTail[0].GetDigest( fullName ).ToArray();
        var e1 = keys.EventTail[1].GetDigest( fullName ).ToArray();

        // In sync, or lagging on our own chain: nothing to say.
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 1, e1 ).ShouldBeFalse();
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 0, e0 ).ShouldBeFalse();
        keys.Alerts.ShouldBeEmpty();

        // A different event at a sequence we hold: someone forked us.
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 1, RandomNumberGenerator.GetBytes( 32 ) ).ShouldBeTrue();
        // A sequence beyond our log: someone rotated us.
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R2/#Dev", 2, RandomNumberGenerator.GetBytes( 32 ) ).ShouldBeTrue();

        var alerts = keys.Alerts;
        alerts.Count.ShouldBe( 2 );
        var forked = alerts.Single( a => a.Kind == IdentityAlertKind.IdentityForked );
        forked.Seq.ShouldBe( 1 );
        forked.ExpectedDigest.ToArray().ShouldBe( e1 );
        forked.ReportedBy.ShouldBe( new[] { "Test/$R1/#Dev" } );
        forked.IsCritical.ShouldBeTrue();
        var takenOver = alerts.Single( a => a.Kind == IdentityAlertKind.IdentityTakenOver );
        takenOver.Seq.ShouldBe( 2 );
        takenOver.ReportedBy.ShouldBe( new[] { "Test/$R2/#Dev" } );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_new_reporter_fires_the_event_again_and_a_repetition_does_not_Async( CancellationToken token )
    {
        const string partyName = "AlertReporters";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, FastClock() );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        var raised = new ConcurrentQueue<IdentityAlert>();
        keys.AlertRaised.Sync += ( monitor, a ) => raised.Enqueue( a );

        var stated = RandomNumberGenerator.GetBytes( 32 );
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 5, stated ).ShouldBeTrue();
        await WaitForAsync( () => raised.Count == 1, token );

        // The same remote repeating itself: counted, not raised again.
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 5, stated ).ShouldBeTrue();
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 5, stated ).ShouldBeTrue();
        // Several heartbeats, so that an event that should not come has had every chance to.
        await Task.Delay( 300, token );
        raised.Count.ShouldBe( 1 );
        var a = keys.Alerts.ShouldHaveSingleItem();
        a.Count.ShouldBe( 3 );

        // Another remote stating the same: stronger evidence, raised again.
        keys.ReportPinStatement( TestHelper.Monitor, "Test/$R2/#Dev", 5, stated ).ShouldBeTrue();
        await WaitForAsync( () => raised.Count == 2, token );
        var last = raised.Last();
        last.Id.ShouldBe( a.Id );
        last.ReportedBy.ShouldBe( new[] { "Test/$R1/#Dev", "Test/$R2/#Dev" } );
        last.Count.ShouldBe( 4 );
        keys.Alerts.ShouldHaveSingleItem();
    }

    [Test, CancelAfter( 30000 )]
    public async Task Every_alert_log_line_carries_the_tag_Async( CancellationToken token )
    {
        const string partyName = "AlertTag";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        var stated = RandomNumberGenerator.GetBytes( 32 );
        using( TestHelper.Monitor.CollectEntries( out var entries, LogLevelFilter.Trace ) )
        {
            keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 3, stated );
            keys.ReportPinStatement( TestHelper.Monitor, "Test/$R1/#Dev", 3, stated );
            keys.Acknowledge( TestHelper.Monitor, keys.Alerts.Single() ).ShouldBeTrue();

            entries.Count.ShouldBe( 3, "Raised, repeated, acknowledged." );
            entries.ShouldAllBe( e => e.Tags.IsSupersetOf( IdentityAlert.LogTag ) );
            entries[0].MaskedLevel.ShouldBe( LogLevel.Error );
            entries[0].Tags.IsSupersetOf( ActivityMonitor.Tags.ToBeInvestigated ).ShouldBeTrue();
        }
    }

    static async Task WaitForAsync( Func<bool> condition, CancellationToken token )
    {
        while( !condition() ) await Task.Delay( 20, token );
    }
}
