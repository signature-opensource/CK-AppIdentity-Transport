using CK.AppIdentity.KeyManagement;
using CK.Testing.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The identity certificate's profile, and the time base it is judged against (finding M10).
/// <para>
/// The identity is the party's certificate authority: it signs message transcripts, and it issues
/// the purpose-specific credentials of <see cref="LocalIdentityKey.CreateDerivedCertificate"/> so
/// that its own private key never has to leave. That is what <c>KeyCertSign</c> and
/// <c>BasicConstraints(CA:true)</c> are for, and the path length constraint of 0 is what keeps the
/// authority to exactly one level.
/// </para>
/// <para>
/// The certificate is public data (<c>Keys/Current.cer</c>): the private key is in the
/// <see cref="ICoreKeyStore"/> and the key event log says which key is current. So a certificate that
/// is wrong is re-minted for the same key, and a certificate near its expiry triggers a rotation to the
/// committed next key. Nothing is trashed on the strength of a certificate.
/// </para>
/// <para>
/// M10 — <see cref="X509Certificate2.NotAfter"/> is local time. Compared raw against
/// <c>SystemClock.UtcNow</c>, the machine's UTC offset leaks into the rotation decision.
/// </para>
/// </summary>
[TestFixture]
public class IdentityCertificateTests
{
    [Test, CancelAfter( 30000 )]
    public async Task The_identity_certificate_is_an_authority_constrained_to_one_level_Async( CancellationToken token )
    {
        // Read back what is actually written to the store rather than what the builder intends to
        // write: the profile is what a peer validating a chain will see.
        const string partyName = "IdProfile";
        IdentityStoreHelper.ClearKeys( partyName );
        await using( await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token ) ) { }

        using var c = IdentityStoreHelper.LoadCurrentCertificate( partyName );

        var constraints = IdentityStoreHelper.GetExtension<X509BasicConstraintsExtension>( c );
        constraints.CertificateAuthority.ShouldBeTrue(
            "The identity issues the credentials other purposes need, which is how its private key " +
            "stays where it is. CertificateRequest.Create refuses a non-CA signer outright." );
        constraints.HasPathLengthConstraint.ShouldBeTrue();
        constraints.PathLengthConstraint.ShouldBe( 0,
            "It may issue leaves and nothing else. Without this, a derived credential could itself " +
            "issue, and a scoped certificate would become a second identity." );

        IdentityStoreHelper.GetExtension<X509KeyUsageExtension>( c ).KeyUsages.ShouldBe(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
            "DigitalSignature signs message transcripts; KeyCertSign issues. Nothing else: this key " +
            "is never used to agree on a secret or to encrypt." );

        IdentityStoreHelper.GetExtension<X509SubjectKeyIdentifierExtension>( c ).Critical.ShouldBeFalse(
            "RFC 5280 §4.2.1.2: conforming CAs MUST mark the Subject Key Identifier non-critical." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_stored_certificate_that_cannot_issue_is_reminted_for_the_same_key_Async( CancellationToken token )
    {
        // A certificate without CA:true cannot sign anything, so every derived credential would fail at
        // connection time. The loader decides it instead - and since the certificate is only public
        // data, it re-mints it: the key, which every remote pinned, does not change.
        const string partyName = "IdNotCA";
        await CheckRemintedAsync( partyName, token, ( key ) =>
            IdentityStoreHelper.WriteCurrentCertificate( partyName, key, DateTime.UtcNow.AddDays( 100 ), certificateAuthority: false ) );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_stored_certificate_of_another_name_is_reminted_for_the_same_key_Async( CancellationToken token )
    {
        const string partyName = "IdOtherName";
        await CheckRemintedAsync( partyName, token, ( key ) =>
            IdentityStoreHelper.WriteCurrentCertificate( partyName, key, DateTime.UtcNow.AddDays( 100 ), commonName: "Test/$SomeoneElse" ) );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_missing_certificate_is_reminted_for_the_same_key_Async( CancellationToken token )
    {
        const string partyName = "IdNoCert";
        await CheckRemintedAsync( partyName, token, _ => File.Delete( IdentityStoreHelper.GetCurrentCertificatePath( partyName ) ) );
    }

    static async Task CheckRemintedAsync( string partyName, CancellationToken token, Action<System.Security.Cryptography.ECDsa> damage )
    {
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        byte[] spki;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            spki = s.GetRequiredFeature<ILocalKeys>().CurrentIdentity.PublicKeyRawData.ToArray();
            using var key = IdentityStoreHelper.OpenKey( s, protector, 0 );
            damage( key );
        }
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.Seq.ShouldBe( 0, "A certificate problem is no reason to rotate." );
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( spki, "Same key." );
        }
        using var c = IdentityStoreHelper.LoadCurrentCertificate( partyName );
        IdentityStoreHelper.GetExtension<X509BasicConstraintsExtension>( c ).CertificateAuthority.ShouldBeTrue();
        c.GetNameInfo( X509NameType.SimpleName, false ).ShouldBe( IdentityStoreHelper.FullName( partyName ) );
        c.PublicKey.ExportSubjectPublicKeyInfo().ShouldBe( spki );
    }

    /// <summary>
    /// Writes a certificate of the current key expiring at <paramref name="notAfterUtc"/>, restarts,
    /// and reports whether the party rotated.
    /// </summary>
    static async Task<bool> RotatesOnRestartAsync( string partyName, DateTime notAfterUtc, CancellationToken token )
    {
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            using var key = IdentityStoreHelper.OpenKey( s, protector, 0 );
            IdentityStoreHelper.WriteCurrentCertificate( partyName, key, notAfterUtc );
        }
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            return s.GetRequiredFeature<ILocalKeys>().Seq == 1;
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_certificate_near_its_expiry_rotates_to_the_next_key_Async( CancellationToken token )
    {
        // Any machine: well inside the threshold (AllowedOfflineDays + 1 day), this must rotate.
        (await RotatesOnRestartAsync( "IdNearExpiry", DateTime.UtcNow.AddDays( 10 ), token )).ShouldBeTrue();
        // And well outside, it must not.
        (await RotatesOnRestartAsync( "IdFarExpiry", DateTime.UtcNow.AddDays( 200 ), token )).ShouldBeFalse();
    }

    [Test, CancelAfter( 60000 )]
    public async Task An_expiring_certificate_rotates_on_its_UTC_expiry_Async( CancellationToken token )
    {
        // M10, east of UTC. A certificate expiring 30 minutes inside the rotation threshold must rotate.
        // Reading NotAfter as if it were UTC adds the machine's offset, which east of UTC pushes it past
        // the threshold and keeps a key that should have rotated.
        var offset = TimeZoneInfo.Local.GetUtcOffset( DateTime.UtcNow );
        if( offset <= TimeSpan.Zero )
        {
            Assert.Ignore( $"Local offset is {offset}: this case only discriminates east of UTC. " +
                            "The bug is invisible in UTC by construction — the two time bases coincide." );
        }
        var threshold = DateTime.UtcNow.AddDays( ILocalKeys.DefaultAllowedOfflineDays + 1 );
        (await RotatesOnRestartAsync( "M10East", threshold.AddMinutes( -30 ), token )).ShouldBeTrue(
            "30 minutes inside the threshold must rotate. Comparing the certificate's local NotAfter " +
            $"against UtcNow added {offset} to it." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_valid_certificate_does_not_rotate_over_a_time_zone_offset_Async( CancellationToken token )
    {
        // M10, west of UTC. A certificate expiring 30 minutes outside the threshold must not rotate.
        var offset = TimeZoneInfo.Local.GetUtcOffset( DateTime.UtcNow );
        if( offset >= TimeSpan.Zero )
        {
            Assert.Ignore( $"Local offset is {offset}: this case only discriminates west of UTC. " +
                            "The bug is invisible in UTC by construction — the two time bases coincide." );
        }
        var threshold = DateTime.UtcNow.AddDays( ILocalKeys.DefaultAllowedOfflineDays + 1 );
        (await RotatesOnRestartAsync( "M10West", threshold.AddMinutes( 30 ), token )).ShouldBeFalse(
            "30 minutes outside the threshold must not rotate. Comparing the certificate's local NotAfter " +
            $"against UtcNow shifted it by {offset}." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_exposed_expiry_is_UTC_Async( CancellationToken token )
    {
        // The public boundary, testable on any machine including UTC: LocalIdentityKey.NotAfter must
        // be the certificate's expiry as a UTC instant, not its local rendering.
        const string partyName = "M10Kind";
        IdentityStoreHelper.ClearKeys( partyName );
        DateTime exposed;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token ) )
        {
            exposed = s.GetRequiredFeature<ILocalKeys>().CurrentIdentity.NotAfter;
        }
        exposed.Kind.ShouldBe( DateTimeKind.Utc );
        using var c = IdentityStoreHelper.LoadCurrentCertificate( partyName );
        exposed.ShouldBe( c.NotAfter.ToUniversalTime() );
    }
}
