using CK.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// A signature a party makes for the application (<see cref="ILocalKeys.Sign"/>) and that any party
/// checks (<see cref="IPartyKeys.Verify"/>): DESIGN-key-pre-rotation §18.
/// <para>
/// It is one value, <see cref="Encoded"/>, to store or send as a whole: <c>version(1) ‖ len16(credential) ‖
/// credential ‖ signature</c>. The two parts can be taken out (<see cref="Credential"/>, <see cref="Signature"/>)
/// and put back together (<see cref="TryCombine"/>): a format that sends the credential once and refers
/// to it from many signatures can do so. Short signatures share the same cached credential for days.
/// </para>
/// <para>
/// Every instance is checked when it is built (by <see cref="ILocalKeys.Sign"/>, <see cref="TryRead"/> or
/// <see cref="TryCombine"/>): the cut between the two parts is read from the bytes themselves.
/// </para>
/// <para>
/// The identity key never signs application data: it issues an <b>application credential</b> (an X.509
/// leaf with its own <see cref="SigningOid"/> extended key usage), whose key signs. A signature made for
/// the application can therefore never pass for a handshake signature, nor the reverse.
/// </para>
/// <para>
/// What is signed is never a bare hash: <c>"CK.AppIdentity.App/0" ‖ expiration ‖ len16(purpose) ‖
/// purpose ‖ data</c>, so a signature made for one purpose is refused for any other, and the expiration
/// the signer chose cannot be extended. The signature carries that expiration: <see cref="SignatureSize"/>
/// is 8 bytes of expiration (UTC ticks, little endian) followed by the 64 bytes of ECDSA P-256 (IEEE P1363).
/// </para>
/// <para>
/// <b>Validity.</b> A signature is valid until its expiration, unless the signer's identity is revoked:
/// <list type="bullet">
///   <item>A regular rotation has no effect: a credential issued by a key that has since been replaced is
///   accepted when it was issued while that key was current (its NotBefore is not after the event that
///   replaced the key).</item>
///   <item>A recovery condemns every credential issued by a key before it.</item>
///   <item>A decommission does not: what was signed runs to its expiration.</item>
///   <item>A credential lives at most the verifier's <see cref="ILocalKeys.AllowedOfflineDays"/>. It bounds
///   what the holder of a stolen, replaced key can still sign by backdating a credential.</item>
/// </list>
/// </para>
/// </summary>
public readonly struct ApplicationSignature
{
    /// <summary>
    /// The extended key usage of an application credential. A UUID-based OID (ITU-T X.667, <c>2.25.{uuid}</c>).
    /// </summary>
    public const string SigningOid = "2.25.99673279988829329152681229999111409432";

    /// <summary>
    /// The size of a signature: the 8 bytes of the expiration and the 64 of the ECDSA signature.
    /// </summary>
    public const int SignatureSize = 8 + 64;

    /// <summary>
    /// The maximal length of a purpose, in UTF-8 bytes.
    /// </summary>
    public const int MaxPurposeLength = 256;

    /// <summary>
    /// The version of the <see cref="Encoded"/> layout.
    /// </summary>
    public const byte Version = 0;

    const int HeaderSize = 3;

    static ReadOnlySpan<byte> DomainTag => "CK.AppIdentity.App/0"u8;

    readonly byte[] _encoded;

    ApplicationSignature( byte[] encoded ) => _encoded = encoded;

    /// <summary>
    /// Gets whether this is the default value: no signature at all.
    /// </summary>
    public bool IsDefault => _encoded == null;

    /// <summary>
    /// Gets the whole value, to store or send.
    /// </summary>
    public ReadOnlyMemory<byte> Encoded => _encoded;

    /// <summary>
    /// Gets the application credential (DER): the X.509 leaf whose key made <see cref="Signature"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Credential => IsDefault ? default : _encoded.AsMemory( HeaderSize, Cut - HeaderSize );

    /// <summary>
    /// Gets the signature (<see cref="SignatureSize"/> bytes): the expiration, then the ECDSA signature.
    /// </summary>
    public ReadOnlyMemory<byte> Signature => IsDefault ? default : _encoded.AsMemory( Cut );

    /// <summary>
    /// Gets the expiration the signer chose (UTC). It is signed: trust it only once verified.
    /// </summary>
    public DateTime Expiration => IsDefault ? default : ReadExpiration( _encoded.AsSpan( Cut ) )!.Value;

    int Cut => HeaderSize + BinaryPrimitives.ReadUInt16LittleEndian( _encoded.AsSpan( 1 ) );

    /// <summary>
    /// Reads a stored or received value. The bytes are copied.
    /// </summary>
    /// <param name="encoded">The <see cref="Encoded"/> bytes.</param>
    /// <param name="signature">Outputs the signature, the default one when the bytes are malformed.</param>
    /// <returns>True if the bytes are well formed (which says nothing of the signature's validity).</returns>
    public static bool TryRead( ReadOnlySpan<byte> encoded, out ApplicationSignature signature )
    {
        signature = default;
        if( encoded.Length < HeaderSize || encoded[0] != Version ) return false;
        int length = BinaryPrimitives.ReadUInt16LittleEndian( encoded.Slice( 1 ) );
        if( !IsValid( length, encoded.Slice( HeaderSize ) ) ) return false;
        signature = new ApplicationSignature( encoded.ToArray() );
        return true;

        static bool IsValid( int length, ReadOnlySpan<byte> rest )
            => length > 0
               && length <= OperationalCredential.MaxEncodedSize
               && rest.Length == length + SignatureSize
               && ReadExpiration( rest.Slice( length ) ) != null;
    }

    /// <summary>
    /// Puts back together a signature whose credential travelled separately.
    /// </summary>
    /// <param name="credential">The <see cref="Credential"/>.</param>
    /// <param name="signaturePart">The <see cref="Signature"/>.</param>
    /// <param name="signature">Outputs the signature, the default one when the parts are malformed.</param>
    /// <returns>True if the parts are well formed (which says nothing of the signature's validity).</returns>
    public static bool TryCombine( ReadOnlySpan<byte> credential, ReadOnlySpan<byte> signaturePart, out ApplicationSignature signature )
    {
        signature = default;
        if( credential.IsEmpty
            || credential.Length > OperationalCredential.MaxEncodedSize
            || signaturePart.Length != SignatureSize
            || ReadExpiration( signaturePart ) == null )
        {
            return false;
        }
        signature = Create( credential, signaturePart );
        return true;
    }

    internal static ApplicationSignature Create( ReadOnlySpan<byte> credential, ReadOnlySpan<byte> signaturePart )
    {
        Throw.DebugAssert( credential.Length > 0 && credential.Length <= OperationalCredential.MaxEncodedSize && signaturePart.Length == SignatureSize );
        var encoded = new byte[HeaderSize + credential.Length + SignatureSize];
        encoded[0] = Version;
        BinaryPrimitives.WriteUInt16LittleEndian( encoded.AsSpan( 1 ), (ushort)credential.Length );
        credential.CopyTo( encoded.AsSpan( HeaderSize ) );
        signaturePart.CopyTo( encoded.AsSpan( HeaderSize + credential.Length ) );
        return new ApplicationSignature( encoded );
    }

    /// <summary>
    /// Computes the hash that is signed.
    /// </summary>
    /// <param name="purpose">The purpose. Not empty, at most <see cref="MaxPurposeLength"/> UTF-8 bytes.</param>
    /// <param name="expiration">The expiration (UTC).</param>
    /// <param name="data">The data.</param>
    /// <returns>The SHA-256 hash.</returns>
    public static byte[] ComputeHash( string purpose, DateTime expiration, ReadOnlySpan<byte> data )
    {
        var p = GetPurposeBytes( purpose );
        Throw.CheckArgument( "The expiration must be a UTC DateTime.", expiration.Kind == DateTimeKind.Utc );
        using var h = IncrementalHash.CreateHash( HashAlgorithmName.SHA256 );
        h.AppendData( DomainTag );
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian( b, expiration.Ticks );
        h.AppendData( b );
        BinaryPrimitives.WriteUInt16LittleEndian( b, (ushort)p.Length );
        h.AppendData( b.Slice( 0, 2 ) );
        h.AppendData( p );
        h.AppendData( data );
        return h.GetHashAndReset();
    }

    static DateTime? ReadExpiration( ReadOnlySpan<byte> signature )
    {
        if( signature.Length != SignatureSize ) return null;
        long ticks = BinaryPrimitives.ReadInt64LittleEndian( signature );
        return ticks >= DateTime.MinValue.Ticks && ticks <= DateTime.MaxValue.Ticks ? new DateTime( ticks, DateTimeKind.Utc ) : null;
    }

    static byte[] GetPurposeBytes( string purpose )
    {
        Throw.CheckNotNullOrEmptyArgument( purpose );
        var p = Encoding.UTF8.GetBytes( purpose );
        Throw.CheckArgument( $"The purpose must be at most {MaxPurposeLength} UTF-8 bytes.", p.Length <= MaxPurposeLength );
        return p;
    }

    /// <summary>
    /// X.509 times are encoded to the second: a credential spans what was asked plus this, at most.
    /// </summary>
    internal static readonly TimeSpan TimePrecisionSlack = TimeSpan.FromSeconds( 2 );

    /// <summary>
    /// Signs a hash computed by <see cref="ComputeHash"/> with an application credential.
    /// </summary>
    internal static ApplicationSignature Sign( OperationalCredential credential, DateTime expiration, ReadOnlySpan<byte> hash )
    {
        Span<byte> signature = stackalloc byte[SignatureSize];
        BinaryPrimitives.WriteInt64LittleEndian( signature, expiration.Ticks );
        Throw.CheckState( credential.TrySignHash( hash, signature.Slice( 8 ), out int written ) && written == 64 );
        return Create( credential.Encoded.Span, signature );
    }

    /// <summary>
    /// Verifies a signature of <paramref name="signerName"/> against what the verifier knows of its key
    /// event log: <paramref name="chain"/>, consecutive events ending at the verifier's head for it.
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="signerName">The signer's full name, for the logs.</param>
    /// <param name="chain">The known events, consecutive, oldest first. Empty when nothing is pinned.</param>
    /// <param name="purpose">The purpose.</param>
    /// <param name="data">The data.</param>
    /// <param name="applicationSignature">The signature.</param>
    /// <param name="now">The verifier's time.</param>
    /// <param name="maxClockOffset">The offset tolerated on the credential's start (never on the expiration).</param>
    /// <param name="maxLifetimeDays">The verifier's bound on a credential's validity: its AllowedOfflineDays.</param>
    /// <returns>True if the signature is valid.</returns>
    internal static bool Verify( IActivityLineEmitter logger,
                                 string signerName,
                                 IReadOnlyList<KeyEvent> chain,
                                 string purpose,
                                 ReadOnlySpan<byte> data,
                                 in ApplicationSignature applicationSignature,
                                 DateTime now,
                                 TimeSpan maxClockOffset,
                                 int maxLifetimeDays )
    {
        if( applicationSignature.IsDefault )
        {
            logger.Warn( $"Signature of '{signerName}' refused: there is none (default value)." );
            return false;
        }
        var credential = applicationSignature.Credential.Span;
        var signature = applicationSignature.Signature.Span;
        if( chain.Count == 0 )
        {
            logger.Warn( $"Signature of '{signerName}' refused: no identity of it is trusted here." );
            return false;
        }
        var expiration = ReadExpiration( signature );
        if( expiration == null )
        {
            logger.Warn( $"Signature of '{signerName}' refused: it is malformed." );
            return false;
        }
        // Strict: the signer's bound is what counts.
        if( now > expiration.Value )
        {
            logger.Info( $"Signature of '{signerName}' refused: it expired on {expiration.Value:u}." );
            return false;
        }
        using var c = OperationalCredential.TryLoad( credential, out var error );
        if( c == null )
        {
            logger.Warn( $"Signature of '{signerName}' refused: {error}" );
            return false;
        }
        error = OperationalCredential.CheckLeaf( c, SigningOid, "application signing" );
        if( error != null )
        {
            logger.Warn( $"Signature of '{signerName}' refused: {error}" );
            return false;
        }
        // The issuer, from the head back. An abandonment reveals a key that never issues anything, a
        // recovery event the recovery key: neither can be an issuer.
        var maxLifetime = TimeSpan.FromDays( maxLifetimeDays ) + TimePrecisionSlack;
        int issuer = -1;
        for( int i = chain.Count - 1; i >= 0; --i )
        {
            // A key replaced longer ago than the longest lifetime issued nothing still valid, and nor did
            // the keys before it: no need to look further.
            if( i < chain.Count - 1 && chain[i + 1].TimeName + maxLifetime < now ) break;
            var e = chain[i];
            if( e.IsAbandonment || e.IsRecovery ) continue;
            if( DerivedCertificateVerifier.IsIssuedBy( c, e.Spki.Span ) )
            {
                issuer = i;
                break;
            }
        }
        if( issuer < 0 )
        {
            logger.Warn( $"Signature of '{signerName}' refused: its credential is not issued by a key of its identity known here." );
            return false;
        }
        for( int j = issuer + 1; j < chain.Count; ++j )
        {
            if( chain[j].IsRecovery )
            {
                logger.Warn( $"Signature of '{signerName}' refused: its credential was issued by key #{chain[issuer].Seq}, condemned by the recovery #{chain[j].Seq}." );
                return false;
            }
        }
        // X509Certificate2.NotBefore/NotAfter are LOCAL time: converted, never compared raw (M10).
        var notBefore = c.NotBefore.ToUniversalTime();
        var notAfter = c.NotAfter.ToUniversalTime();
        if( issuer < chain.Count - 1 )
        {
            // Replaced by the next event: the credential must have been issued while its key was current.
            var replacedAt = chain[issuer + 1].TimeName;
            if( notBefore > replacedAt )
            {
                logger.Warn( $"Signature of '{signerName}' refused: its credential starts on {notBefore:u}, after key #{chain[issuer].Seq} was replaced on {replacedAt:u}." );
                return false;
            }
        }
        if( notAfter - notBefore > maxLifetime )
        {
            // Not a forgery as such: the signer may be configured for longer signatures than this party
            // accepts. Said loudly, because both sides must agree on it.
            logger.Log( LogLevel.Warn, ActivityMonitor.Tags.ToBeInvestigated,
                        $"Signature of '{signerName}' refused: its credential is valid for {(notAfter - notBefore).TotalDays:0.#} days, " +
                        $"more than this party's AllowedOfflineDays = {maxLifetimeDays}. Check that the MaxSignatureDays of '{signerName}' " +
                        $"is not above the AllowedOfflineDays of the parties that verify its signatures." );
            return false;
        }
        if( expiration.Value > notAfter )
        {
            logger.Warn( $"Signature of '{signerName}' refused: it claims to outlive its credential ({notAfter:u})." );
            return false;
        }
        if( now < notBefore - maxClockOffset )
        {
            logger.Warn( $"Signature of '{signerName}' refused: its credential is not yet valid (NotBefore: {notBefore:u})." );
            return false;
        }
        using var key = c.GetECDsaPublicKey();
        if( key == null
            || !key.VerifyHash( ComputeHash( purpose, expiration.Value, data ), signature.Slice( 8 ), DSASignatureFormat.IeeeP1363FixedFieldConcatenation ) )
        {
            logger.Warn( $"Signature of '{signerName}' refused: it does not match the purpose and the data." );
            return false;
        }
        return true;
    }
}
