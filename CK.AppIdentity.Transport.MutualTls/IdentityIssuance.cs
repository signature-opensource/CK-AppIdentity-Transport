using CK.AppIdentity.KeyManagement;
using System;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Answers "was this certificate issued by that identity?" against a <em>bare public key</em>.
/// <para>
/// This exists because of a gap in the platform. A listener holds each remote's pinned identity as a
/// SubjectPublicKeyInfo and nothing more — distributing the identity <em>certificate</em> is the
/// format change the design deliberately did not make. But <see cref="X509Chain"/> can only validate
/// against an <see cref="X509Certificate2"/>, and net8.0 offers no way to verify a certificate's
/// signature against a key on its own. So the signature is checked directly: a certificate is a
/// SEQUENCE of the signed body, the algorithm, and the signature over that body, and all three are
/// readable without reconstructing anything.
/// </para>
/// <para>
/// What this is NOT: a chain validator. It checks one signature and nothing else — not validity
/// dates, not basic constraints, not key usage, not revocation. That is the right scope here, because
/// the answer is used to look up which remote is connecting and is then held against the signed
/// InitialMessage. A certificate that verifies but is expired still has to survive that, and a
/// certificate that does not verify simply leaves the connection on the path it would have taken
/// anyway. Do not reuse this where a real chain verdict is wanted.
/// </para>
/// </summary>
public static class IdentityIssuance
{
    /// <summary>
    /// Gets the Subject Key Identifier an identity's certificate carries, so that a leaf's Authority
    /// Key Identifier can be matched against it.
    /// <para>
    /// This is a cheap filter, not evidence: an Authority Key Identifier is unauthenticated and any
    /// peer can write whatever it likes there. Its only job is to pick one candidate out of a list so
    /// that an unauthenticated connection costs ONE signature verification instead of one per party —
    /// which on a listener serving a large fleet is the difference between a lookup and an
    /// amplifier. A forged value selects a candidate whose signature check then fails, and the
    /// connection falls through to the path it would have taken with no certificate at all.
    /// </para>
    /// </summary>
    // Memoized per key instance. TryResolveRemote calls GetKeyIdentifier once per party per incoming
    // connection, and the computation is an SPKI encode plus a SHA-1 plus a hex-string build - which
    // is exactly the per-party cost this filter exists to remove. Avoiding the ECDSA verification but
    // keeping this made the "lookup, not amplifier" claim in the doc below only half true.
    // ConditionalWeakTable holds no strong reference, so a rotated-out key is collected with its entry.
    static readonly ConditionalWeakTable<IPublicKeyData, string> _keyIdentifiers = new();

    /// <summary>
    /// Gets the key identifier of an identity. Computed once per key instance and cached.
    /// </summary>
    /// <param name="identity">The identity key.</param>
    /// <returns>The key identifier.</returns>
    public static string GetKeyIdentifier( IPublicKeyData identity )
    {
        // Built with the same type that minted it, so the two cannot drift apart over the choice of
        // hash or over what exactly is hashed.
        return _keyIdentifiers.GetValue( identity,
                                         static k => new X509SubjectKeyIdentifierExtension( k.PublicKey, critical: false ).SubjectKeyIdentifier! );
    }

    /// <summary>
    /// Gets the key identifier a certificate names as its issuer, or null when it names none.
    /// </summary>
    public static string? TryGetAuthorityKeyIdentifier( X509Certificate2 certificate )
    {
        foreach( var e in certificate.Extensions )
        {
            if( e is X509AuthorityKeyIdentifierExtension aki && aki.KeyIdentifier.HasValue )
            {
                return Convert.ToHexString( aki.KeyIdentifier.Value.Span );
            }
        }
        return null;
    }

    /// <summary>
    /// Verifies that <paramref name="certificate"/> carries a signature made by <paramref name="identity"/>.
    /// </summary>
    /// <returns>True when the identity's key signed this certificate.</returns>
    public static bool WasIssuedBy( X509Certificate2 certificate, IPublicKeyData identity )
    {
        // One implementation, shared with the Zero Protocol's operational credentials.
        return DerivedCertificateVerifier.IsIssuedBy( certificate, identity.PublicKeyRawData.Span );
    }

}
