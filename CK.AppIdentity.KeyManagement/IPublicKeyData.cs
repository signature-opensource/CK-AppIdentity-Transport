using CK.Core;
using System;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Public key data (no computing capabilities).
/// </summary>
public interface IPublicKeyData
{
    /// <summary>
    /// Gets the <see cref="PublicKey"/>.
    /// </summary>
    PublicKey PublicKey { get; }

    /// <summary>
    /// Gets the <see cref="PublicKey"/> raw data (cache of <see cref="PublicKey.ExportSubjectPublicKeyInfo()"/>):
    /// this is the DER encoded X.509 <c>SubjectPublicKeyInfo</c> (RFC 5280), that holds the key algorithm
    /// and parameters (the curve) and the key itself.
    /// <para>
    /// This is the content of the "Identity.*.public" files of the key store and what is exchanged on the wire.
    /// It can be read back by <see cref="PublicKey.CreateFromSubjectPublicKeyInfo(ReadOnlySpan{byte}, out int)"/>
    /// (or <c>ECDsa.ImportSubjectPublicKeyInfo</c>). Its PEM form is
    /// <c>PemEncoding.WriteString( "PUBLIC KEY", PublicKeyRawData.Span )</c>, the "-----BEGIN PUBLIC KEY-----"
    /// block that OpenSSL reads and writes.
    /// </para>
    /// </summary>
    ReadOnlyMemory<byte> PublicKeyRawData { get; }

    /// <summary>
    /// Gets the "time name" of this key (in <see cref="DateTimeKind.Utc"/>): it is the creation time of the key.
    /// <para>
    /// This name is not intrinsically mandatory, but it helps analyzing and
    /// understanding the system.
    /// </para>
    /// </summary>
    DateTime TimeName { get; }

    /// <summary>
    /// Gets the name of this key: it is the <see cref="TimeName"/> in
    /// the format <see cref="CK.Core.FileUtil.FileNameUniqueTimeUtcFormat"/> and
    /// is the string used by the key store (whatever it is).
    /// <para>
    /// This name is not intrinsically mandatory, but it helps analyzing and
    /// understanding the system.
    /// </para>
    /// </summary>
    string Name { get; }
}

/// <summary>
/// Extends <see cref="IPublicKeyData"/>.
/// </summary>
public static class PublicKeyDataExtensions
{
    /// <summary>
    /// Gets a short, stable, human-comparable fingerprint of <see cref="IPublicKeyData.PublicKeyRawData"/>:
    /// the first 20 bytes of its SHA-256, Base32 encoded, in 8 groups of 4 characters
    /// (for instance "KRSX-G5DJ-NZSX-I4TB-ONSW-G5DF-OJSW-Y3DP").
    /// <para>
    /// This exists to be <c>read out loud</c>. Whenever a key is accepted without having been
    /// verified beforehand (a <c>PeeringIssue</c> approval, or any <see cref="AutoTrustKey"/>
    /// that is not <see cref="AutoTrustKey.Never"/>), the key being trusted is simply the one
    /// the other side just sent: nothing in the protocol proves it belongs to the intended
    /// party. Comparing this fingerprint over an out-of-band channel (phone, chat, ticket) is
    /// what turns that approval into an actual authentication decision.
    /// </para>
    /// </summary>
    /// <param name="this">This public key data.</param>
    /// <returns>The fingerprint.</returns>
    public static string GetFingerprint( this IPublicKeyData @this )
        => PublicKeyFingerprint.Compute( @this.PublicKeyRawData.Span );
}
