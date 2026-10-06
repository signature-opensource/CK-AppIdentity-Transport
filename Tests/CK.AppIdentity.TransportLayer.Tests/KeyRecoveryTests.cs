using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The recovery key (DESIGN-key-pre-rotation §13), as chain rules: what lets an identity be taken back
/// after its NEXT key leaked, and what keeps anyone else from using that power.
/// </summary>
[TestFixture]
public class KeyRecoveryTests
{
    const string Party = "Test/$RecoveryParty/#Dev";

    static ECDsa NewKey() => ECDsa.Create( ECCurve.NamedCurves.nistP256 );
    static byte[] Commit( ECDsa k ) => KeyEvent.ComputeCommit( k.ExportSubjectPublicKeyInfo() );

    /// <summary>
    /// What a thief holding the next key of <paramref name="victim"/> writes: an ordinary event revealing
    /// that key, committing onward to a key of its own. A legitimate-looking rotation: a verifier must
    /// accept it, and it carries the victim's recovery commitment unchanged, since an ordinary event must.
    /// </summary>
    static KeyEvent StolenRotation( PeerIdentity victim, ECDsa thiefNext )
        => KeyEvent.Create( Party, victim.Head.Seq + 1, DateTime.UtcNow, victim.NextKey, Commit( thiefNext ), victim.Head );

    [Test]
    public void a_recovery_supersedes_a_chain_moved_with_a_stolen_next_key()
    {
        using var victim = PeerIdentity.Create( Party );
        var e0 = victim.Head;
        using var thiefNext = NewKey();
        var stolen = StolenRotation( victim, thiefNext );
        // The verifier follows the thief: it cannot tell.
        KeyEventChain.Verify( Party, new[] { e0, stolen }, e0 ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
        stolen.RecoveryCommit.ToArray().ShouldBe( e0.RecoveryCommit.ToArray(), "The thief cannot change the recovery commitment." );

        // The victim recovers: a recovery event at the very sequence the thief used, then a rotation.
        victim.Recover();
        var tail = victim.Tail;
        tail.Select( e => e.Seq ).ShouldBe( new[] { 0, 1, 2 } );
        tail[1].IsRecovery.ShouldBeTrue();

        var c = KeyEventChain.Verify( Party, tail, stolen );
        c.Verdict.ShouldBe( KeyChainVerdict.Recovered );
        c.Head.ShouldBeSameAs( victim.Head );
        c.Held.ShouldBeSameAs( stolen );

        // And a verifier that never saw the thief advances as usual.
        KeyEventChain.Verify( Party, tail, e0 ).Verdict.ShouldBe( KeyChainVerdict.Recovered );
        KeyEventChain.IsValidLog( Party, victim.Events ).ShouldBeTrue( "The owner's own log, with its recovery, verifies." );
    }

    [Test]
    public void after_a_recovery_the_thief_chain_is_worth_nothing()
    {
        using var victim = PeerIdentity.Create( Party );
        var e0 = victim.Head;
        using var thiefNext = NewKey();
        var stolen = StolenRotation( victim, thiefNext );
        victim.Recover();
        var recoveredHead = victim.Head;

        // The thief continues its own chain: it does not link to the recovered pin.
        using var thiefAfter = NewKey();
        var stolen2 = KeyEvent.Create( Party, 2, DateTime.UtcNow, thiefNext, Commit( thiefAfter ), stolen );
        var v = KeyEventChain.Verify( Party, new[] { e0, stolen, stolen2 }, recoveredHead ).Verdict;
        v.ShouldBeOneOf( KeyChainVerdict.Invalid, KeyChainVerdict.Duplicity );
        v.ShouldNotBe( KeyChainVerdict.Advanced );
    }

    [Test]
    public void an_ordinary_event_cannot_change_the_recovery_commitment()
    {
        // A thief with the next key would love to commit the recovery to a key of its own: then the
        // owner could never take the identity back. Every other part of this event is valid.
        using var victim = PeerIdentity.Create( Party );
        using var thiefNext = NewKey();
        using var thiefRecovery = NewKey();
        var forged = Forge( 1, victim.NextKey, victim.NextKey, Commit( thiefNext ), Commit( thiefRecovery ), victim.Head, recovery: false );
        KeyEventChain.Verify( Party, new[] { victim.Head, forged }, victim.Head ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
        // Same event with the recovery commitment carried: accepted. The check above is the only difference.
        var honest = Forge( 1, victim.NextKey, victim.NextKey, Commit( thiefNext ), victim.Head.RecoveryCommit.ToArray(), victim.Head, recovery: false );
        KeyEventChain.Verify( Party, new[] { victim.Head, honest }, victim.Head ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
    }

    [Test]
    public void a_recovery_needs_the_committed_recovery_key()
    {
        using var victim = PeerIdentity.Create( Party );
        using var other = NewKey();
        using var thiefNext = NewKey();
        Should.Throw<ArgumentException>( () => KeyEvent.CreateRecovery( Party, DateTime.UtcNow, other, Commit( thiefNext ), Commit( other ), victim.Head ) );

        // Forged with the recovery flag and any key: neither supersedes nor links.
        var forged = Forge( 1, other, other, Commit( thiefNext ), Commit( other ), victim.Head, recovery: true );
        using var thiefNext2 = NewKey();
        var pinned = StolenRotation( victim, thiefNext2 );
        KeyEventChain.Verify( Party, new[] { forged }, pinned ).Verdict.ShouldNotBe( KeyChainVerdict.Recovered );
        KeyEventChain.Verify( Party, new[] { victim.Head, forged }, victim.Head ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
    }

    [Test]
    public void a_used_recovery_cannot_be_replayed_once_a_new_one_is_committed()
    {
        // A recovery event is public once used. Replayed later, it must not roll anybody back: the
        // recovery commitment it matched has been replaced by the recovery itself.
        using var victim = PeerIdentity.Create( Party );
        var e0 = victim.Head;
        victim.Recover();
        var usedRecovery = victim.Tail.Where( e => e.IsRecovery ).ToList();
        victim.Rotate();
        var later = victim.Head;
        KeyEventChain.Verify( Party, new[] { e0 }.Concat( usedRecovery ).ToList(), later ).Verdict.ShouldNotBe( KeyChainVerdict.Recovered );
    }

    [Test]
    public void a_recovery_supersedes_an_abandonment_written_with_a_stolen_next_key()
    {
        // A thief with the next key can end the identity: a denial of service. The owner takes it back.
        using var victim = PeerIdentity.Create( Party );
        var abandonment = KeyEvent.Create( Party, 1, DateTime.UtcNow, victim.NextKey, ReadOnlySpan<byte>.Empty, victim.Head );
        abandonment.IsAbandonment.ShouldBeTrue();
        KeyEventChain.Verify( Party, new[] { abandonment }, abandonment ).Verdict.ShouldBe( KeyChainVerdict.Terminated );

        victim.Recover();
        KeyEventChain.Verify( Party, victim.Tail, abandonment ).Verdict.ShouldBe( KeyChainVerdict.Recovered );
    }

    [Test]
    public void an_identity_without_a_recovery_key_cannot_be_recovered()
    {
        using var k0 = NewKey();
        using var k1 = NewKey();
        var e0 = KeyEvent.Create( Party, 0, DateTime.UtcNow, k0, Commit( k1 ), null );
        e0.HasRecovery.ShouldBeFalse();
        Should.Throw<ArgumentException>( () => KeyEvent.CreateRecovery( Party, DateTime.UtcNow, k0, Commit( k1 ), default, e0 ) );
    }

    [Test]
    public void recovery_events_round_trip_through_their_encoding()
    {
        using var victim = PeerIdentity.Create( Party );
        victim.Recover();
        foreach( var e in victim.Events )
        {
            var back = KeyEvent.Read( e.Encoded.Span );
            back.IsRecovery.ShouldBe( e.IsRecovery );
            back.RecoveryCommit.ToArray().ShouldBe( e.RecoveryCommit.ToArray() );
            back.GetDigest( Party ).ToArray().ShouldBe( e.GetDigest( Party ).ToArray() );
        }
        // Unknown flag bits are refused rather than ignored.
        var bytes = victim.Events[1].Encoded.ToArray();
        bytes[12] |= 0x80;
        Should.Throw<InvalidDataException>( () => KeyEvent.Read( bytes ) );
    }

    /// <summary>
    /// Builds an event the way an attacker would: any key revealed, any key signing, any recovery
    /// commitment, the recovery flag or not.
    /// </summary>
    static KeyEvent Forge( int seq, ECDsa revealed, ECDsa signer, byte[] nextCommit, byte[] recoveryCommit, KeyEvent previous, bool recovery )
    {
        var spki = revealed.ExportSubjectPublicKeyInfo();
        var prev = previous.GetDigest( Party ).ToArray();
        var t = DateTime.UtcNow;
        t = new DateTime( t.Ticks - (t.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc );
        byte flags = recovery ? (byte)1 : (byte)0;
        var name = System.Text.Encoding.UTF8.GetBytes( Party );
        using var payload = new MemoryStream();
        using( var w = new BinaryWriter( payload, System.Text.Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( "CK.AppIdentity.KEL/0"u8.ToArray() );
            w.Write( (ushort)name.Length );
            w.Write( name );
            w.Write( (uint)seq );
            w.Write( t.Ticks );
            w.Write( flags );
            w.Write( (ushort)spki.Length );
            w.Write( spki );
            w.Write( nextCommit );
            w.Write( recoveryCommit );
            w.Write( prev );
        }
        var sig = signer.SignHash( SHA512.HashData( payload.ToArray() ), DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
        using var encoded = new MemoryStream();
        using( var w = new BinaryWriter( encoded ) )
        {
            w.Write( (uint)seq );
            w.Write( t.Ticks );
            w.Write( flags );
            w.Write( (ushort)spki.Length );
            w.Write( spki );
            w.Write( nextCommit );
            w.Write( recoveryCommit );
            w.Write( prev );
            w.Write( (byte)sig.Length );
            w.Write( sig );
        }
        return KeyEvent.Read( encoded.ToArray() );
    }
}
