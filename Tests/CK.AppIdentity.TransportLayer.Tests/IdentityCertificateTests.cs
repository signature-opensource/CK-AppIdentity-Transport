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
/// Findings M9 and M10: the identity certificate's profile, and the time base it is judged against.
/// <para>
/// M9 — the certificate was minted with <c>KeyCertSign</c> and <c>BasicConstraints(CA:true)</c> for a
/// key whose only job is signing messages. Nothing needs to sign certificates; the one helper that
/// would (<c>LocalKeys.CreateSignedCertificate</c>) has no callers. A certificate that asserts the
/// authority to mint other certificates signs anything if it ever reaches an OS trust store, and is
/// rejected outright by strict validators when presented as an end-entity leaf — which is what a
/// mutual TLS transport would do with it.
/// </para>
/// <para>
/// M10 — <see cref="X509Certificate2.NotAfter"/> is local time and was compared raw against
/// <c>SystemClock.UtcNow</c>, so the machine's UTC offset leaked into the expiry decision. East of
/// UTC a key looks fresher than it is and rotation happens late; west of UTC it looks expired and
/// the loader TRASHES it. This runs on every load, not only on creation.
/// </para>
/// </summary>
[TestFixture]
public class IdentityCertificateTests
{
    static NormalizedPath GetKeysFolder( string partyName )
        => ApplicationIdentityServiceConfiguration.DefaultStoreRootPath
                .Combine( $"#Dev/Test/${partyName}/-Local/Keys" );

    static string[] GetKeyFiles( string partyName )
    {
        var p = GetKeysFolder( partyName );
        return Directory.Exists( p )
                ? Directory.EnumerateFiles( p, "*.pfx" ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    static void ClearKeys( string partyName )
    {
        var p = GetKeysFolder( partyName );
        if( Directory.Exists( p ) ) Directory.Delete( p, recursive: true );
    }

    // The parameter is typed IDataProtectionProvider so that AddSingleton infers THAT service type:
    // the test helper already registered a FakeProtector for it and the last registration wins.
    static Task<ApplicationIdentityService> CreateAsync( string partyName, IDataProtectionProvider protector, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync(
                c => c["FullName"] = $"Test/${partyName}",
                services => services.AddSingleton( protector ),
                token );

    /// <summary>
    /// Loads a stored identity. The PFX password lives in the protected <c>.pwd</c> side file, so
    /// this needs the very protector the service was given.
    /// </summary>
    static X509Certificate2 LoadStoredCertificate( string partyName, IDataProtector protector, string fileName )
    {
        var pfx = GetKeysFolder( partyName ).AppendPart( fileName );
        var pwd = Encoding.UTF8.GetString( protector.Unprotect( File.ReadAllBytes( pfx + ".pwd" ) ) );
        return new X509Certificate2( File.ReadAllBytes( pfx ), pwd );
    }

    static T GetExtension<T>( X509Certificate2 c ) where T : X509Extension
        => c.Extensions.OfType<T>().SingleOrDefault()
           ?? throw new AssertionException( $"No {typeof( T ).Name} on '{c.Subject}'." );

    [Test, CancelAfter( 30000 )]
    public async Task The_identity_certificate_is_an_end_entity_certificate_Async( CancellationToken token )
    {
        // M9. Read back what was actually written to the store rather than what the builder meant
        // to write: the profile is what a TLS peer or an OS trust store will see.
        const string partyName = "M9Profile";
        ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( await CreateAsync( partyName, protector, token ) ) { }

        var files = GetKeyFiles( partyName );
        files.Length.ShouldBe( 1 );
        using var c = LoadStoredCertificate( partyName, protector, files[0] );

        GetExtension<X509BasicConstraintsExtension>( c ).CertificateAuthority.ShouldBeFalse(
            "The identity key signs messages. A key that also asserts it may mint certificates signs " +
            "anything if it ever reaches an OS trust store." );

        GetExtension<X509KeyUsageExtension>( c ).KeyUsages.ShouldBe( X509KeyUsageFlags.DigitalSignature,
            "DigitalSignature and nothing else: that is what signs a message transcript, and what " +
            "would sign a TLS CertificateVerify. KeyCertSign authorises signing other certificates." );

        GetExtension<X509SubjectKeyIdentifierExtension>( c ).Critical.ShouldBeFalse(
            "RFC 5280 §4.2.1.2: conforming CAs MUST mark the Subject Key Identifier non-critical. " +
            "Nothing validated these certificates, so it never showed." );
    }

    /// <summary>
    /// Replaces the party's stored identity with one expiring at <paramref name="notAfterUtc"/>,
    /// reusing the real certificate's subject so the loader's subject check is not what is being
    /// measured. Returns the crafted file name.
    /// </summary>
    static string CraftStoredIdentity( string partyName, IDataProtector protector, DateTime notAfterUtc )
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
        request.CertificateExtensions.Add( new X509KeyUsageExtension( X509KeyUsageFlags.DigitalSignature, true ) );
        request.CertificateExtensions.Add( new X509BasicConstraintsExtension( false, false, 0, true ) );
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
