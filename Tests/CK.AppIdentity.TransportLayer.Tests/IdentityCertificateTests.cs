using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The identity certificate's profile, and the time base it is judged against (finding M10).
/// <para>
/// The identity is the party's certificate authority: it signs message transcripts, and it issues
/// the purpose-specific credentials of <see cref="LocalIdentityKey.CreateDerivedCertificate"/> so
/// that its own private key never has to leave. That is what <c>KeyCertSign</c> and
/// <c>BasicConstraints(CA:true)</c> are for, and the path length constraint of 0 is what keeps the
/// authority to exactly one level: an identity that could issue issuers would let any credential
/// derived from it mint more, which is the difference between a scoped credential and a second
/// identity. What is presented in a TLS handshake is the derived leaf, never this certificate.
/// </para>
/// <para>
/// M10 — <see cref="X509Certificate2.NotAfter"/> is local time. Compared raw against
/// <c>SystemClock.UtcNow</c>, the machine's UTC offset leaks into the expiry decision. East of
/// UTC a key looks fresher than it is and rotation happens late; west of UTC it looks expired and
/// the loader TRASHES it. This runs on every load, not only on creation.
/// </para>
/// </summary>
[TestFixture]
public class IdentityCertificateTests
{
    static NormalizedPath GetKeysFolder( string partyName ) => IdentityStoreHelper.GetKeysFolder( partyName );

    static string[] GetKeyFiles( string partyName ) => IdentityStoreHelper.GetKeyFiles( partyName );

    static void ClearKeys( string partyName ) => IdentityStoreHelper.ClearKeys( partyName );

    static Task<ApplicationIdentityService> CreateAsync( string partyName, IDataProtectionProvider protector, CancellationToken token )
        => IdentityStoreHelper.CreateAsync( partyName, protector, token );

    static X509Certificate2 LoadStoredCertificate( string partyName, IDataProtector protector, string fileName )
        => IdentityStoreHelper.LoadStoredCertificate( partyName, protector, fileName );

    static T GetExtension<T>( X509Certificate2 c ) where T : X509Extension => IdentityStoreHelper.GetExtension<T>( c );

    [Test, CancelAfter( 30000 )]
    public async Task The_identity_certificate_is_an_authority_constrained_to_one_level_Async( CancellationToken token )
    {
        // Read back what is actually written to the store rather than what the builder intends to
        // write: the profile is what a peer validating a chain will see.
        const string partyName = "IdProfile";
        ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( await CreateAsync( partyName, protector, token ) ) { }

        var files = GetKeyFiles( partyName );
        files.Length.ShouldBe( 1 );
        using var c = LoadStoredCertificate( partyName, protector, files[0] );

        var constraints = GetExtension<X509BasicConstraintsExtension>( c );
        constraints.CertificateAuthority.ShouldBeTrue(
            "The identity issues the credentials other purposes need, which is how its private key " +
            "stays where it is. CertificateRequest.Create refuses a non-CA signer outright." );
        constraints.HasPathLengthConstraint.ShouldBeTrue();
        constraints.PathLengthConstraint.ShouldBe( 0,
            "It may issue leaves and nothing else. Without this, a derived credential could itself " +
            "issue, and a scoped certificate would become a second identity." );

        GetExtension<X509KeyUsageExtension>( c ).KeyUsages.ShouldBe(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
            "DigitalSignature signs message transcripts; KeyCertSign issues. Nothing else: this key " +
            "is never used to agree on a secret or to encrypt." );

        GetExtension<X509SubjectKeyIdentifierExtension>( c ).Critical.ShouldBeFalse(
            "RFC 5280 §4.2.1.2: conforming CAs MUST mark the Subject Key Identifier non-critical. " +
            "Only a peer that really parses the certificate notices, which is why it is easy to get " +
            "wrong and stay wrong." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task An_identity_that_cannot_issue_is_rejected_at_load_Async( CancellationToken token )
    {
        // A stored certificate without CA:true cannot sign anything, so every derived credential
        // would fail — at connection time, on every connection, with nothing that repairs itself.
        // The loader decides it instead: the key is trashed and the party rotates on the spot.
        const string partyName = "IdNotCA";
        ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( await CreateAsync( partyName, protector, token ) ) { }

        var crafted = CraftStoredIdentity( partyName, protector, DateTime.UtcNow.AddDays( 30 ), certificateAuthority: false );

        (await CraftedKeySurvivesRestartAsync( partyName, protector, crafted, token )).ShouldBeFalse(
            "An identity that cannot issue is not an identity this system can use." );
    }

    /// <summary>
    /// Replaces the party's stored identity with one expiring at <paramref name="notAfterUtc"/>,
    /// reusing the real certificate's subject so the loader's subject check is not what is being
    /// measured. Returns the crafted file name.
    /// </summary>
    static string CraftStoredIdentity( string partyName,
                                       IDataProtector protector,
                                       DateTime notAfterUtc,
                                       bool certificateAuthority = true )
    {
        var folder = GetKeysFolder( partyName );
        var existing = GetKeyFiles( partyName );
        existing.Length.ShouldBe( 1, "One real key was created first, to copy its subject from." );

        X500DistinguishedName subject;
        using( var real = LoadStoredCertificate( partyName, protector, existing[0] ) )
        {
            subject = real.SubjectName;
        }
        foreach( var f in Directory.EnumerateFiles( folder ).ToArray() ) File.Delete( f );

        using var ecdsa = ECDsa.Create();
        ecdsa.KeySize = 256;
        var request = new CertificateRequest( subject, ecdsa, HashAlgorithmName.SHA256 );
        // The real profile, so that only the expiry (or the CA bit, when a caller asks) is what the
        // loader is being measured on.
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension( X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true ) );
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension( certificateAuthority, certificateAuthority, 0, true ) );
        request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, false ) );

        var now = DateTime.UtcNow;
        // NotBefore is back-dated a day exactly as CreateIdentityCertificate does.
        using var crafted = request.CreateSelfSigned( new DateTimeOffset( now.AddDays( -1 ) ),
                                                      new DateTimeOffset( notAfterUtc ) );

        // The file name must parse as a UTC time name that is already in the past, or FilterFileNames
        // discards it before the expiry check is ever reached.
        var name = now.AddMinutes( -5 ).ToString( FileUtil.FileNameUniqueTimeUtcFormat );
        var fileName = name + ".pfx";
        var pwd = Util.GetRandomBase64UrlString( 20 );
        File.WriteAllBytes( folder.AppendPart( fileName ), crafted.Export( X509ContentType.Pfx, pwd ) );
        File.WriteAllBytes( folder.AppendPart( fileName + ".pwd" ), protector.Protect( Encoding.UTF8.GetBytes( pwd ) ) );
        return fileName;
    }

    /// <summary>
    /// Restarts over the crafted store and reports whether the crafted key survived. A rejected key
    /// is trashed out of the Keys folder and replaced, so its presence is the verdict.
    /// </summary>
    static async Task<bool> CraftedKeySurvivesRestartAsync( string partyName,
                                                            IDataProtectionProvider protector,
                                                            string craftedFileName,
                                                            CancellationToken token )
    {
        await using( await CreateAsync( partyName, protector, token ) ) { }
        return GetKeyFiles( partyName ).Contains( craftedFileName );
    }

    [Test, CancelAfter( 60000 )]
    public async Task An_expiring_certificate_is_rejected_on_its_UTC_expiry_Async( CancellationToken token )
    {
        // M10, east of UTC. The loader rejects a key whose NotAfter is within one day. A key expiring
        // in 23h30m must therefore go. Reading NotAfter as if it were UTC adds the machine's offset,
        // which east of UTC pushes it past the threshold and keeps a key that should have rotated.
        var offset = TimeZoneInfo.Local.GetUtcOffset( DateTime.UtcNow );
        if( offset <= TimeSpan.Zero )
        {
            Assert.Ignore( $"Local offset is {offset}: this case only discriminates east of UTC. " +
                            "The bug is invisible in UTC by construction — the two time bases coincide." );
        }
        const string partyName = "M10East";
        ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( await CreateAsync( partyName, protector, token ) ) { }

        var crafted = CraftStoredIdentity( partyName, protector, DateTime.UtcNow.AddDays( 1 ).AddMinutes( -30 ) );

        (await CraftedKeySurvivesRestartAsync( partyName, protector, crafted, token )).ShouldBeFalse(
            "A key 30 minutes inside the one-day expiry threshold must be rejected. Comparing the " +
            $"certificate's local NotAfter against UtcNow added {offset} to it and kept the key." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_valid_certificate_is_not_trashed_over_a_time_zone_offset_Async( CancellationToken token )
    {
        // M10, west of UTC — the destructive direction. A key expiring in 24h30m is outside the
        // threshold and must be kept. Reading NotAfter as if it were UTC subtracts the offset west of
        // UTC, which drags it inside the threshold: the key is trashed and every remote that pinned
        // it needs a new approval.
        var offset = TimeZoneInfo.Local.GetUtcOffset( DateTime.UtcNow );
        if( offset >= TimeSpan.Zero )
        {
            Assert.Ignore( $"Local offset is {offset}: this case only discriminates west of UTC. " +
                            "The bug is invisible in UTC by construction — the two time bases coincide." );
        }
        const string partyName = "M10West";
        ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( await CreateAsync( partyName, protector, token ) ) { }

        var crafted = CraftStoredIdentity( partyName, protector, DateTime.UtcNow.AddDays( 1 ).AddMinutes( 30 ) );

        (await CraftedKeySurvivesRestartAsync( partyName, protector, crafted, token )).ShouldBeTrue(
            "A key 30 minutes outside the one-day expiry threshold must be kept. Comparing the " +
            $"certificate's local NotAfter against UtcNow shifted it by {offset} and trashed it." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_exposed_expiry_is_UTC_Async( CancellationToken token )
    {
        // The public boundary, testable on any machine including UTC: LocalIdentityKey.NotAfter must
        // be the certificate's expiry as a UTC instant, not its local rendering.
        const string partyName = "M10Kind";
        ClearKeys( partyName );
        var protector = new HeaderProtector();
        DateTime exposed;
        await using( var s = await CreateAsync( partyName, protector, token ) )
        {
            exposed = s.GetRequiredFeature<CK.AppIdentity.KeyManagement.ILocalKeys>().CurrentIdentity.NotAfter;
        }
        exposed.Kind.ShouldBe( DateTimeKind.Utc );

        var files = GetKeyFiles( partyName );
        using var c = LoadStoredCertificate( partyName, protector, files[0] );
        exposed.ShouldBe( c.NotAfter.ToUniversalTime() );
    }
}
