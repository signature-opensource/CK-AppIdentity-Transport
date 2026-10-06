using CK.AppIdentity.KeyManagement;
using CK.Testing.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// <see cref="ILocalKeys.Recover"/>: taking an identity back with its recovery key, held in the key
/// store or offline (DESIGN-key-pre-rotation §13).
/// </summary>
[TestFixture]
public class LocalRecoveryTests
{
    [Test, CancelAfter( 30000 )]
    public async Task Recover_with_the_stored_recovery_key_Async( CancellationToken token )
    {
        const string partyName = "RecStored";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        KeyEvent e0;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            e0 = keys.State.Head;
            e0.HasRecovery.ShouldBeTrue( "Without configuration, the identity commits to a recovery key of the store." );
            IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "0", "1", "recovery-0" } );

            keys.Recover( TestHelper.Monitor ).ShouldBeTrue();
            keys.Seq.ShouldBe( 2, "A recovery event, then the rotation that puts the recovery key back out of use." );
            keys.EventTail.Select( e => e.IsRecovery ).ShouldBe( new[] { false, true, false } );
            KeyEventChain.Verify( IdentityStoreHelper.FullName( partyName ), keys.EventTail, e0 ).Verdict.ShouldBe( KeyChainVerdict.Recovered );
        }
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "2", "3", "recovery-1" },
            "The superseded keys are gone, and a new recovery key replaces the used one." );

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            s.GetRequiredFeature<ILocalKeys>().Seq.ShouldBe( 2, "The recovery survives a restart." );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task Recover_with_an_offline_recovery_key_Async( CancellationToken token )
    {
        const string partyName = "RecOffline";
        IdentityStoreHelper.ClearKeys( partyName );
        using var offline = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        using var nextOffline = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        using var someOther = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                    configure: c => c["RecoveryPublicKey"] = Convert.ToBase64String( offline.ExportSubjectPublicKeyInfo() ) );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        keys.State.Head.CommitsToRecovery( offline.ExportSubjectPublicKeyInfo() ).ShouldBeTrue();
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "0", "1" }, "Nothing of the recovery key is on this host." );

        keys.Recover( TestHelper.Monitor ).ShouldBeFalse( "The recovery key is offline: it must be brought back." );
        keys.Recover( TestHelper.Monitor, someOther, nextOffline.ExportSubjectPublicKeyInfo() ).ShouldBeFalse( "Not the committed key." );
        keys.Recover( TestHelper.Monitor, offline ).ShouldBeFalse( "The next offline recovery key must be named." );
        keys.Seq.ShouldBe( 0 );

        keys.Recover( TestHelper.Monitor, offline, nextOffline.ExportSubjectPublicKeyInfo() ).ShouldBeTrue();
        keys.Seq.ShouldBe( 2 );
        keys.State.Head.CommitsToRecovery( nextOffline.ExportSubjectPublicKeyInfo() ).ShouldBeTrue( "The next recovery is the next offline key." );
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "2", "3" } );
    }

    [Test, CancelAfter( 30000 )]
    public async Task An_interrupted_recovery_is_completed_at_start_Async( CancellationToken token )
    {
        // Crash after the recovery event, before the ordinary event that follows it: the head reveals
        // the recovery key, which signs nothing else. The start finishes the recovery.
        const string partyName = "RecCrash";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        var fullName = IdentityStoreHelper.FullName( partyName );
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var store = new DefaultCoreKeyStore( protector );
            var e0 = s.GetRequiredFeature<ILocalKeys>().State.Head;
            using var recovery = store.OpenKey( TestHelper.Monitor, s, "recovery-0" )!;
            var nextSpki = store.CreateKey( TestHelper.Monitor, s, "2" );
            var nextRecoverySpki = store.CreateKey( TestHelper.Monitor, s, "recovery-1" );
            var r = KeyEvent.CreateRecovery( fullName, DateTime.UtcNow, recovery, KeyEvent.ComputeCommit( nextSpki.Span ),
                                             KeyEvent.ComputeCommit( nextRecoverySpki.Span ), e0 );
            File.WriteAllBytes( IdentityStoreHelper.GetKelFolder( partyName ).AppendPart( "1.event" ), r.Encoded.ToArray() );
        }
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Seq.ShouldBe( 2 );
            keys.EventTail[1].IsRecovery.ShouldBeTrue();
        }
        IdentityStoreHelper.GetKeyNames( partyName ).ShouldBe( new[] { "2", "3", "recovery-1" } );
    }
}
