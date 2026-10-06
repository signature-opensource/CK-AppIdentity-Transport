using CK.AppIdentity.KeyManagement;
using CK.Monitoring;
using CK.Testing.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The local identity on top of the key event log and the <see cref="ICoreKeyStore"/>
/// (DESIGN-key-pre-rotation §9): rotation, its crash points, a lost next key, decommissioning.
/// </summary>
[TestFixture]
public class LocalKeysTests
{
    [Test, CancelAfter( 30000 )]
    public async Task Rotate_moves_to_the_committed_next_key_and_persists_Async( CancellationToken token )
    {
        const string partyName = "LkRotate";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        byte[] nextSpki;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Seq.ShouldBe( 0 );
            var inception = keys.EventTail.Single();
            using( var next = IdentityStoreHelper.OpenKey( s, protector, 1 ) )
            {
                nextSpki = next.ExportSubjectPublicKeyInfo();
            }
            inception.CommitsTo( nextSpki ).ShouldBeTrue();

            var identitiesBefore = keys.Identities;
            keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();

            keys.Seq.ShouldBe( 1 );
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( nextSpki, "The new current key is the one committed to." );
            keys.Identities.ShouldNotBeSameAs( identitiesBefore, "A rotation replaces the list instance: that is how it is detected." );
            keys.EventTail.Count.ShouldBe( 2 );
            KeyEventChain.Verify( IdentityStoreHelper.FullName( partyName ), keys.EventTail, inception ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
        }
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "1", "2", "recovery-0" }, "The previous key is destroyed, a new next one exists." );
        IdentityStoreHelper.GetEventFiles( partyName ).ShouldBe( new[] { "0.event", "1.event" } );
        using( var c = IdentityStoreHelper.LoadCurrentCertificate( partyName ) )
        {
            c.PublicKey.ExportSubjectPublicKeyInfo().ShouldBe( nextSpki );
        }

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Seq.ShouldBe( 1, "The rotation survives a restart." );
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( nextSpki );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_rotation_that_crashed_before_its_commit_point_is_discarded_Async( CancellationToken token )
    {
        // Crash after step 2: the key after next exists, but no event commits to it.
        const string partyName = "LkCrashBefore";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            new DefaultCoreKeyStore( protector ).CreateKey( TestHelper.Monitor, s, "2" );
        }
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "0", "1", "2", "recovery-0" } );

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            s.GetRequiredFeature<ILocalKeys>().Seq.ShouldBe( 0 );
        }
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "0", "1", "recovery-0" }, "Nothing commits to key 2: it is deleted." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_rotation_that_crashed_after_its_commit_point_is_completed_Async( CancellationToken token )
    {
        // Crash after step 3: the event is written, but the certificate is still the previous key's and
        // the previous key still exists.
        const string partyName = "LkCrashAfter";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        byte[] nextSpki;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var store = new DefaultCoreKeyStore( protector );
            var inception = s.GetRequiredFeature<ILocalKeys>().EventTail.Single();
            using var next = IdentityStoreHelper.OpenKey( s, protector, 1 );
            nextSpki = next.ExportSubjectPublicKeyInfo();
            var afterNext = store.CreateKey( TestHelper.Monitor, s, "2" );
            var e = KeyEvent.Create( IdentityStoreHelper.FullName( partyName ), 1, DateTime.UtcNow, next, KeyEvent.ComputeCommit( afterNext.Span ), inception );
            File.WriteAllBytes( IdentityStoreHelper.GetKelFolder( partyName ).AppendPart( "1.event" ), e.Encoded.ToArray() );
        }

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Seq.ShouldBe( 1, "The log is the truth: the rotation happened." );
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( nextSpki );
        }
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "1", "2", "recovery-0" }, "The previous key is deleted." );
        using var c = IdentityStoreHelper.LoadCurrentCertificate( partyName );
        c.PublicKey.ExportSubjectPublicKeyInfo().ShouldBe( nextSpki, "The certificate is re-minted for the current key." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_lost_next_key_is_loud_and_the_party_keeps_working_Async( CancellationToken token )
    {
        const string partyName = "LkNextLost";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( await IdentityStoreHelper.CreateAsync( partyName, protector, token ) ) { }
        File.Delete( IdentityStoreHelper.GetCoreKeysFolder( partyName ).AppendPart( "1.key" ) );

        using var logs = GrandOutput.Default!.CreateMemoryCollector( 1000 );
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Seq.ShouldBe( 0, "The current key still works." );
            logs.ExtractCurrentTexts().ShouldContain( t => t.Contains( "is missing: this party can neither rotate nor be revoked", StringComparison.Ordinal ),
                "Said at start, not discovered at the first rotation." );

            keys.Rotate( TestHelper.Monitor ).ShouldBeFalse();
            keys.Decommission( TestHelper.Monitor ).ShouldBeFalse();
            keys.Seq.ShouldBe( 0 );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_next_key_that_is_not_the_committed_one_cannot_be_used_Async( CancellationToken token )
    {
        // Someone with write access to the key store replaces the next key by one of their own: the
        // commitment refuses it, so the store's content alone cannot hand over the identity.
        const string partyName = "LkNextSwapped";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var store = new DefaultCoreKeyStore( protector );
            store.DeleteKey( TestHelper.Monitor, s, "1" ).ShouldBeTrue();
            store.CreateKey( TestHelper.Monitor, s, "1" );

            var keys = s.GetRequiredFeature<ILocalKeys>();
            using var logs = GrandOutput.Default!.CreateMemoryCollector( 1000 );
            keys.Rotate( TestHelper.Monitor ).ShouldBeFalse();
            keys.Seq.ShouldBe( 0 );
            // KeyEvent.Create would refuse the key too, but later and less clearly: the store's content
            // is checked against the commitment before anything is created.
            logs.ExtractCurrentTexts().ShouldContain( t => t.Contains( "is not the one event #0 committed to", StringComparison.Ordinal ) );
            IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "0", "1", "recovery-0" }, "Nothing was created on the way to the refusal." );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task Decommission_ends_the_identity_and_the_party_refuses_to_start_Async( CancellationToken token )
    {
        const string partyName = "LkDecommission";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Decommission( TestHelper.Monitor ).ShouldBeTrue();
            keys.IsDecommissioned.ShouldBeTrue();
            keys.EventTail[^1].IsAbandonment.ShouldBeTrue();
            keys.Rotate( TestHelper.Monitor ).ShouldBeFalse();
            keys.Decommission( TestHelper.Monitor ).ShouldBeFalse();
        }
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBeEmpty( "Every key is destroyed." );
        IdentityStoreHelper.GetEventFiles( partyName ).ShouldBe( new[] { "0.event", "1.event" } );

        // The next start must fail rather than quietly create a new identity in its place.
        using var logs = GrandOutput.Default!.CreateMemoryCollector( 1000 );
        await Should.ThrowAsync<CK.Core.CKException>( () => IdentityStoreHelper.CreateAsync( partyName, protector, token ) );
        logs.ExtractCurrentTexts().ShouldContain( t => t.Contains( "While initializing LocalKeys feature", StringComparison.Ordinal ) );
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBeEmpty( "And no new key was created." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Files_of_the_previous_layout_are_trashed_Async( CancellationToken token )
    {
        const string partyName = "LkLegacy";
        IdentityStoreHelper.ClearKeys( partyName );
        Directory.CreateDirectory( IdentityStoreHelper.GetKeysFolder( partyName ) );
        var pfx = IdentityStoreHelper.GetKeysFolder( partyName ).AppendPart( "2026-01-01 00.00.00.0000000.pfx" );
        File.WriteAllBytes( pfx, new byte[] { 1 } );
        File.WriteAllBytes( pfx + ".pwd", new byte[] { 1 } );

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token ) )
        {
            s.GetRequiredFeature<ILocalKeys>().Seq.ShouldBe( 0 );
        }
        File.Exists( pfx ).ShouldBeFalse();
        File.Exists( pfx + ".pwd" ).ShouldBeFalse();
    }
}
