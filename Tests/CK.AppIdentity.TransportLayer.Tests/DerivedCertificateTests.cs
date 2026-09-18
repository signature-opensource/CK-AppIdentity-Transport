using CK.AppIdentity.KeyManagement;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// <see cref="LocalIdentityKey.CreateDerivedCertificate"/>: the identity issues credentials instead
/// of lending its key.
/// <para>
/// The property these tests are really about is containment. A transport that needs an
/// <c>X509Certificate2</c> with a usable private key — mutual TLS is the first — gets one that was
/// generated for it and signed by the identity, so the identity private key never crosses a package
/// boundary, the credential can be scoped and short-lived, and throwing it away costs nothing. The
/// weaker arrangement is to hand out the identity key itself: one key for every purpose, and
/// nothing to withdraw short of rotating the identity that every remote has pinned.
/// </para>
/// </summary>
[TestFixture]
public class DerivedCertificateTests
{
    const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// Starts a party and hands its current identity to <paramref name="test"/>, along with the
    /// stored certificate to use as a chain root.
    /// </summary>
    static async Task WithIdentityAsync( string partyName,
                                          Action<LocalIdentityKey, X509Certificate2> test,
                                          CancellationToken token )
    {
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            var key = s.GetRequiredFeature<ILocalKeys>().CurrentIdentity;
            using var root = IdentityStoreHelper.LoadTheStoredCertificate( partyName, protector );
            test( key, root );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_derived_certificate_chains_to_the_identity_Async( CancellationToken token )
    {
        await WithIdentityAsync( "DerivedChain", ( key, root ) =>
        {
            using var derived = key.CreateDerivedCertificate();

            // Chain building is the whole claim: "issued by the identity" is not a convention here,
            // it is a signature a validator checks. Nothing in this system requires it today (§4's
            // 2c binds the certificate by attestation instead), which is exactly why it is asserted —
            // an issuance that is malformed stays silent until something finally validates it.
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add( root );
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            chain.Build( derived ).ShouldBeTrue(
                "Chain status: " + string.Join( ", ", chain.ChainStatus.Select( s => s.StatusInformation.Trim() ) ) );
            chain.ChainElements.Count.ShouldBe( 2, "The leaf and the identity that issued it, and nothing between." );

            // And the same build without that root must fail, or the assertion above says nothing
            // about who signed what — only that X509Chain was willing to return true.
            using var untrusted = new X509Chain();
            untrusted.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            untrusted.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            untrusted.Build( derived ).ShouldBeFalse( "Nothing but the issuing identity vouches for this certificate." );

            derived.IssuerName.RawData.ShouldBe( root.SubjectName.RawData );

            var constraints = IdentityStoreHelper.GetExtension<X509BasicConstraintsExtension>( derived );
            constraints.CertificateAuthority.ShouldBeFalse(
                "A derived credential is a leaf. The identity says pathLen 0, so a validator would " +
                "refuse a CA here anyway, but a certificate should state what it is." );
        }, token );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_derived_certificate_carries_a_key_pair_of_its_own_Async( CancellationToken token )
    {
        await WithIdentityAsync( "DerivedOwnKey", ( key, root ) =>
        {
            using var derived = key.CreateDerivedCertificate();

            derived.PublicKey.ExportSubjectPublicKeyInfo().ShouldNotBe( key.PublicKeyRawData.ToArray(),
                "This is the point of issuing rather than lending: the credential is a different key. " +
                "Were it the same, giving it away would give away the identity." );

            using var priv = derived.GetECDsaPrivateKey();
            priv.ShouldNotBeNull( "SslStream needs a certificate with a usable private key." );
            using var pub = derived.GetECDsaPublicKey();
            var data = new byte[] { 1, 2, 3, 4 };
            var signature = priv.SignData( data, HashAlgorithmName.SHA256 );
            pub!.VerifyData( data, signature, HashAlgorithmName.SHA256 ).ShouldBeTrue();

            using var other = key.CreateDerivedCertificate();
            other.PublicKey.ExportSubjectPublicKeyInfo().ShouldNotBe( derived.PublicKey.ExportSubjectPublicKeyInfo(),
                "Each call generates its own key pair, so one credential's exposure is not another's." );
            other.SerialNumber.ShouldNotBe( derived.SerialNumber, "Serial numbers must be unique per issuer." );
        }, token );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Configure_states_the_purpose_and_cannot_touch_the_issuance_Async( CancellationToken token )
    {
        await WithIdentityAsync( "DerivedConfigure", ( key, root ) =>
        {
            using var derived = key.CreateDerivedCertificate( configure: r =>
                r.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension( new OidCollection { new Oid( ServerAuthOid ), new Oid( ClientAuthOid ) },
                                                       critical: false ) ) );

            var eku = IdentityStoreHelper.GetExtension<X509EnhancedKeyUsageExtension>( derived );
            eku.EnhancedKeyUsages.Cast<Oid>().Select( o => o.Value ).ShouldBe( new[] { ServerAuthOid, ClientAuthOid } );

            IdentityStoreHelper.GetExtension<X509KeyUsageExtension>( derived ).KeyUsages
                .ShouldBe( X509KeyUsageFlags.DigitalSignature,
                    "The default, since the caller said nothing: what an ECDSA TLS credential signs with." );

            // Refused, not overwritten and not appended. A certificate carrying two BasicConstraints
            // is one that some validators accept and others reject — the worst of both, and it would
            // be found by whichever peer happens to be strict.
            Should.Throw<ArgumentException>( () => key.CreateDerivedCertificate( configure: r =>
                r.CertificateExtensions.Add( new X509BasicConstraintsExtension( true, false, 0, true ) ) ) );

            Should.Throw<ArgumentException>( () => key.CreateDerivedCertificate( configure: r =>
                r.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( r.PublicKey, false ) ) ) );
        }, token );
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_derived_validity_is_nested_inside_the_identity_Async( CancellationToken token )
    {
        await WithIdentityAsync( "DerivedValidity", ( key, root ) =>
        {
            using var byDefault = key.CreateDerivedCertificate();
            byDefault.NotAfter.ToUniversalTime().ShouldBe( key.NotAfter );
            byDefault.NotBefore.ToUniversalTime().ShouldBe( key.NotBefore );

            var shorter = key.NotAfter.AddDays( -1 );
            using var scoped = key.CreateDerivedCertificate( notAfter: shorter );
            scoped.NotAfter.ToUniversalTime().ShouldBe( shorter );

            // Outliving the issuer is refused rather than clamped: a credential that expires after
            // the certificate that signed it cannot be chain validated once the issuer is gone, and
            // silently shortening what a caller asked for hides that from them.
            Should.Throw<ArgumentException>( () => key.CreateDerivedCertificate( notAfter: key.NotAfter.AddDays( 1 ) ) );

            // X509Certificate2.NotAfter is LOCAL time, so a caller reading one and passing it back
            // would shift the expiry by the machine's offset — up to 14 hours, never reported. The
            // same time base confusion as finding M10, one layer up.
            Should.Throw<ArgumentException>(
                () => key.CreateDerivedCertificate( notAfter: DateTime.SpecifyKind( key.NotAfter.AddDays( -1 ), DateTimeKind.Local ) ) );
        }, token );
    }
}
