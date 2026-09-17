using System;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests.Adversarial;

/// <summary>
/// An identity key the adversarial peer signs with: an ECDSA P-256 key pair plus the "TimeName"
/// that identifies it on the wire.
/// <para>
/// Unlike the production <c>LocalIdentityKey</c> this is not backed by a certificate or a key
/// store — the Zero Protocol only ever transmits the SubjectPublicKeyInfo and a signature, so a
/// bare key pair is everything a peer needs. That is itself worth knowing: <b>possession of any
/// P-256 key pair is enough to produce a signature the protocol will verify</b>. Whether that
/// signature means anything is the entire subject of finding C2.
/// </para>
/// </summary>
sealed class PeerIdentity : IDisposable
{
    readonly ECDsa _key;

    PeerIdentity( ECDsa key, DateTime timeName )
    {
        _key = key;
        TimeName = timeName;
        SubjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
    }

    /// <summary>
    /// Creates a fresh identity. <paramref name="timeName"/> defaults to "a moment ago" so the key
    /// looks like one created before the current negotiation.
    /// </summary>
    public static PeerIdentity Create( DateTime? timeName = null )
    {
        var k = ECDsa.Create();
        k.KeySize = 256;
        var t = timeName ?? DateTime.UtcNow.AddMinutes( -1 );
        if( t.Kind != DateTimeKind.Utc ) throw new ArgumentException( "TimeName must be UTC.", nameof( timeName ) );
        // The production store truncates to the file-name time format; keep milliseconds only so
        // that a TimeName survives a round-trip through any textual representation unchanged.
        t = new DateTime( t.Ticks - (t.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc );
        return new PeerIdentity( k, t );
    }

    /// <summary>The key's creation time, as it appears on the wire.</summary>
    public DateTime TimeName { get; }

    /// <summary>The public key, in the encoding the Zero Protocol transmits.</summary>
    public byte[] SubjectPublicKeyInfo { get; }

    /// <summary>
    /// Signs a hash in the format the protocol expects
    /// (<see cref="DSASignatureFormat.IeeeP1363FixedFieldConcatenation"/>, i.e. r‖s).
    /// </summary>
    public byte[] SignHash( ReadOnlySpan<byte> hash )
        => _key.SignHash( hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );

    public void Dispose() => _key.Dispose();
}

/// <summary>
/// The harness's ephemeral ECDH key pair for one connection, mirroring what a real peer creates
/// per <c>Transport</c>. Exists so an adversarial test can also present a WRONG or reused
/// ephemeral, which a real peer never would.
/// </summary>
sealed class PeerEphemeral : IDisposable
{
    readonly ECDiffieHellman _key;

    public PeerEphemeral()
    {
        _key = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        PublicKey = _key.PublicKey.ExportSubjectPublicKeyInfo();
    }

    /// <summary>The public half, as it travels on the wire.</summary>
    public byte[] PublicKey { get; }

    /// <summary>The key pair, for deriving the session when the harness needs to speak the run phase.</summary>
    public ECDiffieHellman Key => _key;

    public void Dispose() => _key.Dispose();
}
