using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// DESIGN-key-pre-rotation §18: <see cref="ILocalKeys.Sign"/> and <see cref="IPartyKeys.Verify"/>.
/// <para>
/// A signature is valid until the expiration its signer chose, unless the signer's identity is revoked:
/// a regular rotation has no effect, a recovery condemns, a decommission lets it run. The local side is
/// driven through the real <see cref="ILocalKeys"/>; the remote side through a <see cref="PeerIdentity"/>
/// whose credentials the tests shape at will, which is how forgeries are made.
/// </para>
/// </summary>
[TestFixture]
public class ApplicationSignatureTests
{
    const string Purpose = "CK.Test.Token";
    static readonly byte[] Data = "the data"u8.ToArray();

    // No heartbeat: what a test observes is what it did, and the clock moves only when it says so.
    static SystemClockTester NewClock() => new SystemClockTester( 0 );

    static Action<MutableConfigurationSection> Days( int? operational = null, int? maxSignature = null, int? allowedOffline = null )
        => c =>
        {
            if( operational.HasValue ) c["OperationalKeyDays"] = operational.Value.ToString();
            if( maxSignature.HasValue ) c["MaxSignatureDays"] = maxSignature.Value.ToString();
            if( allowedOffline.HasValue ) c["AllowedOfflineDays"] = allowedOffline.Value.ToString();
        };

    #region Local side

    [Test, CancelAfter( 30000 )]
    public async Task A_signature_verifies_for_its_purpose_and_data_only_Async( CancellationToken token )
    {
        const string partyName = "AppSigBasic";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        var signed = keys.Sign( Purpose, Data, DateTime.UtcNow.AddHours( 1 ) );
        signed.Signature.Length.ShouldBe( ApplicationSignature.SignatureSize );
        signed.Encoded.Length.ShouldBe( 3 + signed.Credential.Length + ApplicationSignature.SignatureSize );

        // Whatever the party is: IPartyKeys is the feature to ask for.
        var party = s.GetRequiredFeature<IPartyKeys>();
        party.ShouldBeSameAs( keys );
        party.Verify( TestHelper.Monitor, Purpose, Data, signed ).ShouldBeTrue();

        party.Verify( TestHelper.Monitor, "CK.Test.Other", Data, signed ).ShouldBeFalse( "Bound to its purpose." );
        party.Verify( TestHelper.Monitor, Purpose, "other data"u8, signed ).ShouldBeFalse( "Bound to its data." );
        party.Verify( TestHelper.Monitor, Purpose, Data, default ).ShouldBeFalse( "No signature at all." );

        // The expiration is signed: extending it breaks the signature.
        var extended = signed.Signature.ToArray();
        BinaryPrimitives.WriteInt64LittleEndian( extended, DateTime.UtcNow.AddDays( 1 ).Ticks );
        ApplicationSignature.TryCombine( signed.Credential.Span, extended, out var tampered ).ShouldBeTrue();
        party.Verify( TestHelper.Monitor, Purpose, Data, tampered ).ShouldBeFalse( "The expiration cannot be extended." );

        // An operational credential of the same identity is not an application credential.
        ApplicationSignature.TryCombine( keys.State.Operational.Encoded.Span, signed.Signature.Span, out var swapped ).ShouldBeTrue();
        party.Verify( TestHelper.Monitor, Purpose, Data, swapped ).ShouldBeFalse( "Purpose separation of the credentials." );
    }

    [Test]
    public void The_encoded_value_splits_and_rebuilds()
    {
        // One value to store or send; its two parts can travel apart and be put back together.
        using var peer = PeerIdentity.Create( "Test/$AppSigEncoding/#Dev" );
        var signed = PeerSign( peer.CurrentKey, peer.FullName, DateTime.UtcNow.AddHours( 1 ) );
        var bytes = signed.Encoded.ToArray();
        bytes[0].ShouldBe( ApplicationSignature.Version );

        ApplicationSignature.TryRead( bytes, out var read ).ShouldBeTrue();
        read.Credential.ToArray().ShouldBe( signed.Credential.ToArray() );
        read.Signature.ToArray().ShouldBe( signed.Signature.ToArray() );
        read.Expiration.ShouldBe( signed.Expiration );
        ApplicationSignature.TryCombine( read.Credential.Span, read.Signature.Span, out var rebuilt ).ShouldBeTrue();
        rebuilt.Encoded.ToArray().ShouldBe( bytes );
        bytes[^1] ^= 1;
        read.Encoded.ToArray()[^1].ShouldNotBe( bytes[^1], "TryRead copies: changing the source changes nothing." );

        // Malformed: refused before any verification.
        ApplicationSignature.TryRead( [], out var none ).ShouldBeFalse();
        none.IsDefault.ShouldBeTrue();
        ApplicationSignature.TryRead( [1, .. bytes.AsSpan( 1 )], out _ ).ShouldBeFalse( "Unknown version." );
        ApplicationSignature.TryRead( bytes.AsSpan( 0, bytes.Length - 1 ), out _ ).ShouldBeFalse( "Truncated." );
        ApplicationSignature.TryRead( [.. bytes, 0], out _ ).ShouldBeFalse( "Trailing bytes." );
        var badLength = bytes.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian( badLength.AsSpan( 1 ), (ushort)(signed.Credential.Length + 1) );
        ApplicationSignature.TryRead( badLength, out _ ).ShouldBeFalse( "The cut does not match the size." );
        ApplicationSignature.TryCombine( [], signed.Signature.Span, out _ ).ShouldBeFalse();
        ApplicationSignature.TryCombine( signed.Credential.Span, signed.Signature.Span[1..], out _ ).ShouldBeFalse();
        var badTicks = signed.Signature.ToArray();
        BinaryPrimitives.WriteInt64LittleEndian( badTicks, long.MaxValue );
        ApplicationSignature.TryCombine( signed.Credential.Span, badTicks, out _ ).ShouldBeFalse( "Not a date." );
        var badDate = signed.Encoded.ToArray();
        BinaryPrimitives.WriteInt64LittleEndian( badDate.AsSpan( 3 + signed.Credential.Length ), long.MaxValue );
        ApplicationSignature.TryRead( badDate, out _ ).ShouldBeFalse( "Not a date: Expiration could not be read." );

        default( ApplicationSignature ).Credential.IsEmpty.ShouldBeTrue();
    }

    [Test, CancelAfter( 30000 )]
    public async Task Sign_refuses_what_it_cannot_guarantee_Async( CancellationToken token )
    {
        const string partyName = "AppSigRefuse";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, configure: Days( maxSignature: 3 ) );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        keys.MaxSignatureDays.ShouldBe( 3 );
        Should.Throw<ArgumentException>( () => keys.Sign( Purpose, Data, DateTime.UtcNow.AddSeconds( -1 ) ) );
        Should.Throw<ArgumentException>( () => keys.Sign( Purpose, Data, DateTime.UtcNow.AddDays( 3 ).AddMinutes( 1 ) ), "Never silently shortened." );
        Should.Throw<ArgumentException>( () => keys.Sign( Purpose, Data, DateTime.Now.AddHours( 1 ) ), "UTC only." );
        Should.Throw<ArgumentException>( () => keys.Sign( "", Data, DateTime.UtcNow.AddHours( 1 ) ) );
        keys.Sign( Purpose, Data, DateTime.UtcNow.AddDays( 3 ).AddMinutes( -1 ) ).Signature.Length.ShouldBe( ApplicationSignature.SignatureSize );
    }

    [Test, CancelAfter( 30000 )]
    public async Task MaxSignatureDays_is_bounded_by_AllowedOfflineDays_Async( CancellationToken token )
    {
        const string partyName = "AppSigBound";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, configure: Days( maxSignature: 40, allowedOffline: 30 ) );
        s.GetRequiredFeature<ILocalKeys>().MaxSignatureDays.ShouldBe( 30 );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_long_signature_gets_a_one_shot_credential_Async( CancellationToken token )
    {
        // The cached credential lives the shortest of OperationalKeyDays and MaxSignatureDays (2 days here).
        // Beyond it, a credential is issued for that one signature, valid exactly until its expiration.
        const string partyName = "AppSigOneShot";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, configure: Days( operational: 2, maxSignature: 7 ) );
        var keys = s.GetRequiredFeature<ILocalKeys>();

        var a = keys.Sign( Purpose, Data, DateTime.UtcNow.AddHours( 1 ) );
        var b = keys.Sign( Purpose, Data, DateTime.UtcNow.AddHours( 2 ) );
        a.Credential.ToArray().ShouldBe( b.Credential.ToArray(), "Short signatures share the cached credential." );

        var expiration = DateTime.UtcNow.AddDays( 5 );
        var c = keys.Sign( Purpose, Data, expiration );
        c.Credential.ToArray().ShouldNotBe( a.Credential.ToArray() );
        using( var cert = X509CertificateLoader.LoadCertificate( c.Credential.Span ) )
        {
            var notAfter = cert.NotAfter.ToUniversalTime();
            notAfter.ShouldBeGreaterThanOrEqualTo( expiration.AddSeconds( -1 ) );
            notAfter.ShouldBeLessThanOrEqualTo( expiration.AddSeconds( 1 ), "Valid exactly until the expiration." );
            cert.NotBefore.ToUniversalTime().ShouldBeGreaterThan( DateTime.UtcNow.AddMinutes( -1 ), "It states its issue time." );
        }
        keys.Verify( TestHelper.Monitor, Purpose, Data, c ).ShouldBeTrue();
        keys.Verify( TestHelper.Monitor, Purpose, Data, a ).ShouldBeTrue();
    }

    [Test, CancelAfter( 30000 )]
    public async Task An_old_identity_still_signs_Async( CancellationToken token )
    {
        // A credential states its issue time. Inheriting the identity's NotBefore, a credential issued by
        // a 55 day old key would claim a validity of 62 days, beyond any AllowedOfflineDays (60): refused.
        const string partyName = "AppSigOld";
        IdentityStoreHelper.ClearKeys( partyName );
        var clock = NewClock();
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, clock );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        clock.Offset = TimeSpan.FromDays( 55 );
        var signed = keys.Sign( Purpose, Data, clock.UtcNow.AddDays( 1 ) );
        keys.Seq.ShouldBe( 0, "Not due for rotation yet." );
        keys.Verify( TestHelper.Monitor, Purpose, Data, signed ).ShouldBeTrue();
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_expiration_is_strict_Async( CancellationToken token )
    {
        const string partyName = "AppSigExpire";
        IdentityStoreHelper.ClearKeys( partyName );
        var clock = NewClock();
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, clock );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        var expiration = clock.UtcNow.AddHours( 1 );
        var signed = keys.Sign( Purpose, Data, expiration );
        signed.Expiration.ShouldBe( expiration );

        clock.Offset = TimeSpan.FromHours( 1 ) - TimeSpan.FromSeconds( 5 );
        keys.Verify( TestHelper.Monitor, Purpose, Data, signed ).ShouldBeTrue();
        clock.Offset = TimeSpan.FromHours( 1 ) + TimeSpan.FromSeconds( 1 );
        keys.Verify( TestHelper.Monitor, Purpose, Data, signed ).ShouldBeFalse( "No tolerance on the signer's bound." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Rotation_keeps_signatures_recovery_condemns_them_decommission_lets_them_run_Async( CancellationToken token )
    {
        const string partyName = "AppSigLife";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token );
        var keys = s.GetRequiredFeature<ILocalKeys>();

        var before = keys.Sign( Purpose, Data, DateTime.UtcNow.AddDays( 1 ) );
        keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        keys.Verify( TestHelper.Monitor, Purpose, Data, before ).ShouldBeTrue( "Two regular rotations: no effect." );

        var rotated = keys.Sign( Purpose, Data, DateTime.UtcNow.AddDays( 1 ) );
        keys.Recover( TestHelper.Monitor ).ShouldBeTrue();
        keys.Verify( TestHelper.Monitor, Purpose, Data, before ).ShouldBeFalse( "The recovery condemns them." );
        keys.Verify( TestHelper.Monitor, Purpose, Data, rotated ).ShouldBeFalse();

        var recovered = keys.Sign( Purpose, Data, DateTime.UtcNow.AddDays( 1 ) );
        keys.Verify( TestHelper.Monitor, Purpose, Data, recovered ).ShouldBeTrue();

        keys.Decommission( TestHelper.Monitor ).ShouldBeTrue();
        keys.Verify( TestHelper.Monitor, Purpose, Data, recovered ).ShouldBeTrue( "A decommission lets them run." );
        Should.Throw<InvalidOperationException>( () => keys.Sign( Purpose, Data, DateTime.UtcNow.AddDays( 1 ) ) );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_long_running_party_rotates_from_the_heartbeat_Async( CancellationToken token )
    {
        // Scheduled rotation used to happen only at start: a process that never restarted kept its key
        // until its certificate expired.
        const string partyName = "AppSigHeartbeat";
        IdentityStoreHelper.ClearKeys( partyName );
        var clock = new SystemClockTester( 50 );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, clock );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        keys.Seq.ShouldBe( 0 );
        var signed = keys.Sign( Purpose, Data, clock.UtcNow.AddDays( 7 ) );

        // The key lives 2 x 60 days and is due once less than 61 are left.
        clock.Offset = TimeSpan.FromDays( 60 );
        for( int i = 0; i < 100 && keys.Seq == 0; ++i ) await Task.Delay( 50, token );
        keys.Seq.ShouldBe( 1, "Rotated by the heartbeat." );
        keys.Verify( TestHelper.Monitor, Purpose, Data, signed ).ShouldBeFalse( "Expired by now." );
        clock.Offset = TimeSpan.Zero;
    }

    #endregion

    #region Remote side

    async Task<(ApplicationIdentityService Service, IRemoteKeys Keys, PeerIdentity Peer)> CreateRemoteAsync( string name,
                                                                                                               SystemClockTester clock,
                                                                                                               CancellationToken token,
                                                                                                               bool clear = true )
    {
        if( clear )
        {
            PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
            PeerStore.ClearLocalParty( $"Test/${name}" );
        }
        var s = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Parties:0:PartyName"] = $"${name}Peer";
        }, services => services.AddSingleton<ApplicationIdentityService.ISystemClock>( clock ), token: token );
        var keys = s.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>();
        return (s, keys, null!);
    }

    static string PeerName( string name ) => $"Test/${name}Peer/#Dev";

    static NormalizedPath HistoryFolder( string name )
        => ApplicationIdentityServiceConfiguration.DefaultStoreRootPath.Combine( $"#Dev/Test/${name}Peer/KeyHistory" );

    /// <summary>
    /// Signs as a peer would, with a credential shaped by the test: how forgeries are made.
    /// </summary>
    static ApplicationSignature PeerSign( ECDsa identityKey,
                                          string fullName,
                                          DateTime expiration,
                                          DateTime? notBefore = null,
                                          DateTime? notAfter = null,
                                          string ekuOid = ApplicationSignature.SigningOid )
    {
        using var c = PeerCredential.Issue( identityKey,
                                            fullName,
                                            notBefore ?? DateTime.UtcNow.AddMinutes( -1 ),
                                            // X.509 times are to the second: rounded up, as Sign does.
                                            notAfter ?? expiration.AddTicks( TimeSpan.TicksPerSecond - expiration.Ticks % TimeSpan.TicksPerSecond ),
                                            ekuOid );
        var signature = new byte[ApplicationSignature.SignatureSize];
        BinaryPrimitives.WriteInt64LittleEndian( signature, expiration.Ticks );
        c.Key.SignHash( ApplicationSignature.ComputeHash( Purpose, expiration, Data ), signature.AsSpan( 8 ), DSASignatureFormat.IeeeP1363FixedFieldConcatenation )
            .ShouldBe( 64 );
        ApplicationSignature.TryCombine( c.Encoded, signature, out var result ).ShouldBeTrue();
        return result;
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_remote_keeps_verifying_across_rotations_and_restarts_Async( CancellationToken token )
    {
        const string name = "AppSigRemote";
        var clock = NewClock();
        var (service, keys, _) = await CreateRemoteAsync( name, clock, token );
        using var peer = PeerIdentity.Create( PeerName( name ) );
        try
        {
            ((IPartyKeys)keys).Party.ShouldBeSameAs( keys.Party );
            var unpinned = PeerSign( peer.CurrentKey, peer.FullName, DateTime.UtcNow.AddDays( 1 ) );
            keys.Verify( TestHelper.Monitor, Purpose, Data, unpinned ).ShouldBeFalse( "Nothing pinned: nothing verified." );

            keys.SetTrustedIdentity( TestHelper.Monitor, peer.Head ).ShouldBeTrue();
            var s0 = PeerSign( peer.CurrentKey, peer.FullName, DateTime.UtcNow.AddDays( 1 ) );
            keys.Verify( TestHelper.Monitor, Purpose, Data, s0 ).ShouldBeTrue();

            peer.Rotate();
            var s1 = PeerSign( peer.CurrentKey, peer.FullName, DateTime.UtcNow.AddDays( 1 ) );
            peer.Rotate();
            keys.ApplyTail( TestHelper.Monitor, peer.Tail ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
            keys.Verify( TestHelper.Monitor, Purpose, Data, s0 ).ShouldBeTrue( "Signed by key #0, replaced since." );
            keys.Verify( TestHelper.Monitor, Purpose, Data, s1 ).ShouldBeTrue( "Signed by key #1, never seen as current here." );
            Directory.EnumerateFiles( HistoryFolder( name ) ).Select( Path.GetFileName ).Order().ShouldBe( ["0.event", "1.event"] );

            await service.DisposeAsync();
            (service, keys, _) = await CreateRemoteAsync( name, clock, token, clear: false );
            keys.TrustedEvent!.Seq.ShouldBe( 2 );
            keys.Verify( TestHelper.Monitor, Purpose, Data, s0 ).ShouldBeTrue( "The history is persisted: a restart verifies the same." );
            keys.Verify( TestHelper.Monitor, Purpose, Data, s1 ).ShouldBeTrue();
        }
        finally
        {
            await service.DisposeAsync();
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_replaced_key_cannot_sign_after_its_replacement_for_long_Async( CancellationToken token )
    {
        // What a thief holding a replaced key can still do: issue a credential backdated to before the
        // rotation, for at most this party's AllowedOfflineDays. Anything else is refused.
        const string name = "AppSigBackdate";
        var clock = NewClock();
        var (service, keys, _) = await CreateRemoteAsync( name, clock, token );
        await using var _svc = service;
        using var peer = PeerIdentity.Create( PeerName( name ) );
        keys.SetTrustedIdentity( TestHelper.Monitor, peer.Head ).ShouldBeTrue();
        var stolen = peer.CurrentKey;
        var rotatedAt = DateTime.UtcNow.AddMinutes( -10 );
        peer.Rotate( rotatedAt );
        keys.ApplyTail( TestHelper.Monitor, peer.Tail ).Verdict.ShouldBe( KeyChainVerdict.Advanced );

        var expiration = DateTime.UtcNow.AddDays( 1 );
        var honest = PeerSign( stolen, peer.FullName, expiration, notBefore: rotatedAt.AddMinutes( -1 ) );
        keys.Verify( TestHelper.Monitor, Purpose, Data, honest ).ShouldBeTrue( "Issued while the key was current." );

        var late = PeerSign( stolen, peer.FullName, expiration, notBefore: rotatedAt.AddMinutes( 1 ) );
        keys.Verify( TestHelper.Monitor, Purpose, Data, late ).ShouldBeFalse( "Issued after the key was replaced." );

        var tooLong = PeerSign( stolen, peer.FullName, expiration, notBefore: DateTime.UtcNow.AddDays( -61 ) );
        keys.Verify( TestHelper.Monitor, Purpose, Data, tooLong ).ShouldBeFalse(
            "Backdated further than AllowedOfflineDays (60): refused, with a warning." );

        var outlives = PeerSign( stolen, peer.FullName, expiration, notBefore: rotatedAt.AddMinutes( -1 ), notAfter: expiration.AddHours( -1 ) );
        keys.Verify( TestHelper.Monitor, Purpose, Data, outlives ).ShouldBeFalse( "A signature cannot outlive its credential." );

        var stranger = PeerSign( ECDsa.Create( ECCurve.NamedCurves.nistP256 ), peer.FullName, expiration );
        keys.Verify( TestHelper.Monitor, Purpose, Data, stranger ).ShouldBeFalse( "Not issued by a key of the identity." );

        var transcript = PeerSign( peer.CurrentKey, peer.FullName, expiration, ekuOid: OperationalCredential.TranscriptSigningOid );
        keys.Verify( TestHelper.Monitor, Purpose, Data, transcript ).ShouldBeFalse(
            "Signed by a handshake credential of the current key: purpose separation." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_remote_recovery_condemns_a_decommission_does_not_Async( CancellationToken token )
    {
        const string name = "AppSigRevoke";
        var clock = NewClock();
        var (service, keys, _) = await CreateRemoteAsync( name, clock, token );
        await using var _svc = service;
        using var peer = PeerIdentity.Create( PeerName( name ) );
        keys.SetTrustedIdentity( TestHelper.Monitor, peer.Head ).ShouldBeTrue();
        var s0 = PeerSign( peer.CurrentKey, peer.FullName, DateTime.UtcNow.AddDays( 1 ) );
        peer.Rotate();
        keys.ApplyTail( TestHelper.Monitor, peer.Tail ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
        keys.Verify( TestHelper.Monitor, Purpose, Data, s0 ).ShouldBeTrue();

        peer.Recover();
        keys.ApplyTail( TestHelper.Monitor, peer.Tail ).Verdict.ShouldBe( KeyChainVerdict.Recovered );
        keys.Verify( TestHelper.Monitor, Purpose, Data, s0 ).ShouldBeFalse( "Condemned by the recovery." );
        Directory.EnumerateFiles( HistoryFolder( name ) ).Select( Path.GetFileName ).ShouldBe( [$"{peer.Head.Seq - 1}.event"],
            "Only the recovery event remains: everything before it is condemned." );

        var s1 = PeerSign( peer.CurrentKey, peer.FullName, DateTime.UtcNow.AddDays( 1 ) );
        peer.Abandon();
        keys.ApplyTail( TestHelper.Monitor, peer.Tail ).Verdict.ShouldBe( KeyChainVerdict.Abandoned );
        keys.Verify( TestHelper.Monitor, Purpose, Data, s1 ).ShouldBeTrue( "A decommission lets them run." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task The_history_is_pruned_once_nothing_it_issued_can_be_valid_Async( CancellationToken token )
    {
        const string name = "AppSigPrune";
        var clock = new SystemClockTester( 50 );
        var (service, keys, _) = await CreateRemoteAsync( name, clock, token );
        await using var _svc = service;
        using var peer = PeerIdentity.Create( PeerName( name ) );
        keys.SetTrustedIdentity( TestHelper.Monitor, peer.Head ).ShouldBeTrue();
        peer.Rotate();
        keys.ApplyTail( TestHelper.Monitor, peer.Tail ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
        Directory.EnumerateFiles( HistoryFolder( name ) ).Count().ShouldBe( 1 );

        clock.Offset = TimeSpan.FromDays( 60 ) - TimeSpan.FromHours( 1 );
        await Task.Delay( 300, token );
        Directory.EnumerateFiles( HistoryFolder( name ) ).Count().ShouldBe( 1, "Within AllowedOfflineDays of its replacement: kept." );

        clock.Offset = TimeSpan.FromDays( 60 ) + TimeSpan.FromHours( 1 );
        for( int i = 0; i < 100 && Directory.EnumerateFiles( HistoryFolder( name ) ).Any(); ++i ) await Task.Delay( 50, token );
        Directory.EnumerateFiles( HistoryFolder( name ) ).ShouldBeEmpty( "Pruned by the heartbeat." );
        clock.Offset = TimeSpan.Zero;
    }

    #endregion
}
