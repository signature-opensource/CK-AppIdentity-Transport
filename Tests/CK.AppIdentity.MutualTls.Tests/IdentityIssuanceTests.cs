using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.MutualTls.Tests;

/// <summary>
/// Verifying a derived certificate against a bare pinned public key.
/// <para>
/// A listener holds each remote's identity as a SubjectPublicKeyInfo and nothing more, and net8.0
/// will not verify a certificate against a key on its own — <see cref="X509Chain"/> wants an
/// <see cref="X509Certificate2"/> for the issuer, which is the format change the design refused to
/// make. So the signature is checked directly. These tests are what makes that hand-rolled split of
/// the DER trustworthy: it must accept the real thing and refuse everything else.
/// </para>
/// </summary>
[TestFixture]
public class IdentityIssuanceTests
{
    static async Task<ApplicationIdentityService> CreateAsync( string partyName, CancellationToken token )
        => await AppIdentityTestHelper.CreateServiceAsync( c => c["FullName"] = $"Test/${partyName}", token: token );

    [Test, CancelAfter( 30000 )]
    public async Task A_derived_certificate_verifies_against_the_identity_that_issued_it_Async( CancellationToken token )
    {
        await using var a = await CreateAsync( "IssuanceA", token );
        await using var b = await CreateAsync( "IssuanceB", token );

        var identityA = a.GetRequiredFeature<ILocalKeys>().CurrentIdentity;
        var identityB = b.GetRequiredFeature<ILocalKeys>().CurrentIdentity;

        using var derived = identityA.CreateDerivedCertificate();

        // A remote holds the pinned key in this shape, and nothing else of the issuer.
        var pinnedA = new RemoteIdentityKey( identityA );
        var pinnedB = new RemoteIdentityKey( identityB );

        IdentityIssuance.WasIssuedBy( derived, pinnedA ).ShouldBeTrue(
            "The whole point: a bare SubjectPublicKeyInfo is enough to prove who issued this." );
        IdentityIssuance.WasIssuedBy( derived, pinnedB ).ShouldBeFalse(
            "Another party's identity did not sign it, and saying otherwise would make the lookup " +
            "worthless — every certificate would resolve to every remote." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_self_signed_stranger_verifies_against_nobody_Async( CancellationToken token )
    {
        // What an unknown peer presents, and what anything terminating the channel would present:
        // a perfectly valid certificate that no identity in this fleet issued.
        await using var a = await CreateAsync( "IssuanceStranger", token );
        var identity = a.GetRequiredFeature<ILocalKeys>().CurrentIdentity;
        var pinned = new RemoteIdentityKey( identity );

        using var stranger = PeerCertificate.Create();
        IdentityIssuance.WasIssuedBy( stranger.Certificate, pinned ).ShouldBeFalse();
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_tampered_certificate_does_not_verify_Async( CancellationToken token )
    {
        // The signature must actually cover the body. Flipping one bit inside the signed region and
        // still getting true would mean the split picked the wrong bytes — a mistake that would pass
        // every other test in this file.
        await using var a = await CreateAsync( "IssuanceTampered", token );
        var identity = a.GetRequiredFeature<ILocalKeys>().CurrentIdentity;
        var pinned = new RemoteIdentityKey( identity );

        using var derived = identity.CreateDerivedCertificate();
        var der = derived.RawData;

        // Byte 30 is well inside the tbsCertificate: past the outer SEQUENCE header, the version and
        // the serial number, and nowhere near the trailing signature.
        der[30] ^= 0xFF;
        using var tampered = new X509Certificate2( der );
        IdentityIssuance.WasIssuedBy( tampered, pinned ).ShouldBeFalse();
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_authority_key_identifier_names_the_issuing_identity_Async( CancellationToken token )
    {
        // The cheap filter that keeps the lookup from costing one verification per party. It is a
        // hint and nothing more - a peer writes whatever it likes there - but it must at least be
        // right for honest certificates, or the filter would discard every real peer.
        await using var a = await CreateAsync( "IssuanceAki", token );
        var identity = a.GetRequiredFeature<ILocalKeys>().CurrentIdentity;

        using var derived = identity.CreateDerivedCertificate();

        IdentityIssuance.TryGetAuthorityKeyIdentifier( derived )
            .ShouldBe( IdentityIssuance.GetKeyIdentifier( new RemoteIdentityKey( identity ) ),
                "Computed from the pinned public key alone, and it matches what the issuer wrote." );

        using var stranger = PeerCertificate.Create();
        IdentityIssuance.TryGetAuthorityKeyIdentifier( stranger.Certificate ).ShouldBeNull(
            "A self-signed stranger names no authority, so the filter discards it without any " +
            "cryptography at all." );
    }
}
