using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Testing.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// <see cref="OperationalCredential.TryVerify"/>: what a verifier accepts as the key that signs a
/// handshake (DESIGN-key-pre-rotation §5). Each refusal is one property away from a credential that is
/// accepted, so each test measures exactly one check.
/// </summary>
[TestFixture]
public class OperationalCredentialTests
{
    const string Party = "Test/$CredParty/#Dev";
    static readonly TimeSpan Offset = TimeSpan.FromMinutes( 5 );

    static bool Accepts( PeerIdentity issuer, PeerCredential credential, DateTime? now = null )
    {
        using var key = OperationalCredential.TryVerify( credential.Encoded, issuer.Head.Spki.Span, now ?? DateTime.UtcNow, Offset, out _, out var error );
        if( key == null ) TestContext.Out.WriteLine( $"Refused: {error}" );
        return key != null;
    }

    [Test]
    public void a_well_formed_credential_is_accepted()
    {
        using var issuer = PeerIdentity.Create( Party );
        using var c = PeerCredential.Issue( issuer.CurrentKey, Party );
        Accepts( issuer, c ).ShouldBeTrue( "The baseline: every refusal below differs from this by one property." );
    }

    [Test]
    public void an_expired_or_not_yet_valid_credential_is_refused()
    {
        using var issuer = PeerIdentity.Create( Party );
        var now = DateTime.UtcNow;
        using var expired = PeerCredential.Issue( issuer.CurrentKey, Party, notBefore: now.AddDays( -3 ), notAfter: now.AddHours( -1 ) );
        Accepts( issuer, expired ).ShouldBeFalse();
        using var future = PeerCredential.Issue( issuer.CurrentKey, Party, notBefore: now.AddHours( 1 ), notAfter: now.AddDays( 3 ) );
        Accepts( issuer, future ).ShouldBeFalse();
        // Within the clock offset both ways, it is accepted: the clocks of two peers are trusted that far.
        using var justExpired = PeerCredential.Issue( issuer.CurrentKey, Party, notBefore: now.AddDays( -3 ), notAfter: now.AddMinutes( -2 ) );
        Accepts( issuer, justExpired ).ShouldBeTrue();
    }

    [Test]
    public void a_credential_valid_for_too_long_is_refused_even_correctly_signed()
    {
        // The verifier bounds what it accepts, whatever the issuer is configured with.
        using var issuer = PeerIdentity.Create( Party );
        using var overlong = PeerCredential.Issue( issuer.CurrentKey, Party, notAfter: DateTime.UtcNow.AddDays( ILocalKeys.MaxOperationalKeyDays + 1 ) );
        Accepts( issuer, overlong ).ShouldBeFalse();
        using var atTheBound = PeerCredential.Issue( issuer.CurrentKey, Party, notAfter: DateTime.UtcNow.AddDays( ILocalKeys.MaxOperationalKeyDays ) );
        Accepts( issuer, atTheBound ).ShouldBeTrue();
    }

    [Test]
    public void a_credential_issued_by_the_previous_identity_key_is_refused_once_rotated()
    {
        // A rotation revokes every credential at once: they are verified against the head's key.
        using var issuer = PeerIdentity.Create( Party );
        using var before = PeerCredential.Issue( issuer.CurrentKey, Party );
        Accepts( issuer, before ).ShouldBeTrue();
        issuer.Rotate();
        Accepts( issuer, before ).ShouldBeFalse();
        Accepts( issuer, issuer.Credential ).ShouldBeTrue();
    }

    [Test]
    public void a_credential_for_another_purpose_is_refused()
    {
        using var issuer = PeerIdentity.Create( Party );
        // What the mTLS credential says: server authentication. Same issuer, other purpose.
        using var tls = PeerCredential.Issue( issuer.CurrentKey, Party, ekuOid: "1.3.6.1.5.5.7.3.1" );
        Accepts( issuer, tls ).ShouldBeFalse();
        using var none = PeerCredential.Issue( issuer.CurrentKey, Party, ekuOid: null );
        Accepts( issuer, none ).ShouldBeFalse();
        using var ca = PeerCredential.Issue( issuer.CurrentKey, Party, certificateAuthority: true );
        Accepts( issuer, ca ).ShouldBeFalse();
    }

    [Test]
    public void garbage_is_refused_without_throwing()
    {
        using var issuer = PeerIdentity.Create( Party );
        OperationalCredential.TryVerify( new byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 }, issuer.Head.Spki.Span, DateTime.UtcNow, Offset, out _, out _ ).ShouldBeNull();
        OperationalCredential.TryVerify( new byte[OperationalCredential.MaxEncodedSize + 1], issuer.Head.Spki.Span, DateTime.UtcNow, Offset, out _, out _ ).ShouldBeNull();
    }

    [Test, CancelAfter( 30000 )]
    public async Task the_production_credential_verifies_against_its_head_Async( CancellationToken token )
    {
        const string partyName = "CredProd";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token );
        var state = s.GetRequiredFeature<ILocalKeys>().State;
        using var key = OperationalCredential.TryVerify( state.Operational.Encoded.Span, state.Head.Spki.Span, DateTime.UtcNow, Offset, out var notAfter, out var error );
        key.ShouldNotBeNull( error );
        notAfter.ShouldBe( DateTime.UtcNow.AddDays( ILocalKeys.DefaultOperationalKeyDays ), TimeSpan.FromMinutes( 1 ) );
        key.ExportSubjectPublicKeyInfo().ShouldNotBe( state.Head.Spki.ToArray(), "The credential key is not the identity key." );
    }
}
