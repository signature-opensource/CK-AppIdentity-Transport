using CK.Core;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The encryption for a party, with the encryption key it publishes in its description (see <see cref="PartyEncryptionKey"/>,
/// <see cref="ILocalKeys.GetEncryptionKey"/>).
/// <para>
/// HPKE-like: an ephemeral ECDH P-256 key agreement with the recipient's encryption key, HKDF-SHA256 (salted with the
/// recipient's key identifier, the ephemeral public key in its info, like HPKE binds enc), then AES-256-GCM. The
/// associated data binds the ciphertext to its context (what the caller gives) and to its creation time: it cannot be
/// moved to another context, and an old one is refused. The shared secret also gives a <b>response key</b>: the recipient
/// encrypts its answer with it (<see cref="EncryptResponse"/>), only the sender can read it.
/// </para>
/// <para>
/// A ciphertext is: keyId(8) ‖ len16(ephemeral SPKI) ‖ ephemeral SPKI ‖ ticks(8) ‖ nonce(12) ‖ tag(16) ‖ cipher.
/// A response is: nonce(12) ‖ tag(16) ‖ cipher.
/// </para>
/// </summary>
public static class PartyEncryption
{
    /// <summary>
    /// The purpose of the signature of a published encryption key by its party.
    /// </summary>
    public const string KeyPurpose = "CK.Party.EncryptionKey";

    /// <summary>
    /// How long an encryption key is published: 1 day.
    /// </summary>
    public static readonly TimeSpan KeyLifetime = TimeSpan.FromDays( 1 );

    /// <summary>
    /// The overlap between two encryption keys: 10 minutes. A new key is published this time before the end of the
    /// current one, and an ended key is still usable this time after its end (for what has been encrypted just before).
    /// </summary>
    public static readonly TimeSpan KeyOverlap = TimeSpan.FromMinutes( 10 );

    /// <summary>
    /// The length of the identifier of an encryption key (see <see cref="GetKeyId"/>).
    /// </summary>
    public const int KeyIdLength = 8;

    static readonly byte[] _encryptionInfo = "CK.Party.Encryption.v1"u8.ToArray();
    static readonly byte[] _responseInfo = "CK.Party.Response.v1"u8.ToArray();
    const int _nonceLength = 12;
    const int _tagLength = 16;

    /// <summary>
    /// Gets the identifier of an encryption key: the beginning of the SHA-256 of its public key.
    /// </summary>
    /// <param name="spki">The public key (SubjectPublicKeyInfo).</param>
    /// <returns>The identifier.</returns>
    public static byte[] GetKeyId( ReadOnlySpan<byte> spki ) => SHA256.HashData( spki ).AsSpan( 0, KeyIdLength ).ToArray();

    /// <summary>
    /// Reads a published encryption key of a party: its signature by the party is checked (for the <see cref="KeyPurpose"/>,
    /// with the party's keys). The reason of a refusal is logged.
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="signer">The keys of the party that published the key (a pinned remote, or a local party).</param>
    /// <param name="key">The published key.</param>
    /// <param name="publicKey">The public key (SubjectPublicKeyInfo) when the key is valid.</param>
    /// <param name="expiration">The end of use of the key when it is valid: the expiration of its signature.</param>
    /// <returns>The verdict: <see cref="SignatureVerdict.UnknownIssuer"/> may become valid once the party's last key events are known.</returns>
    public static SignatureVerdict Check( IActivityLineEmitter logger, IPartyKeys signer, PartyEncryptionKey key, out byte[]? publicKey, out DateTime expiration )
    {
        Throw.CheckNotNullArgument( signer );
        Throw.CheckNotNullArgument( key );
        publicKey = null;
        expiration = default;
        if( !ApplicationSignature.TryRead( key.Signature.Span, out var signature ) )
        {
            logger.Warn( $"The encryption key of '{signer.Party}' is refused: its signature is malformed." );
            return SignatureVerdict.Refused;
        }
        var verdict = signer.Check( logger, KeyPurpose, key.PublicKey.Span, signature );
        if( verdict == SignatureVerdict.Valid )
        {
            publicKey = key.PublicKey.ToArray();
            expiration = signature.Expiration;
        }
        return verdict;
    }

    /// <summary>
    /// Encrypts data for a recipient.
    /// </summary>
    /// <param name="recipientSpki">The encryption key of the recipient (SubjectPublicKeyInfo).</param>
    /// <param name="plain">The data to encrypt.</param>
    /// <param name="associatedData">The context: the recipient must give the same to decrypt.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="responseKey">The key with which the recipient encrypts its answer (see <see cref="TryDecryptResponse"/>).</param>
    /// <returns>The ciphertext.</returns>
    public static byte[] Encrypt( ReadOnlySpan<byte> recipientSpki, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> associatedData, DateTime utcNow, out byte[] responseKey )
    {
        using var recipient = ECDiffieHellman.Create();
        recipient.ImportSubjectPublicKeyInfo( recipientSpki, out _ );
        using var ephemeral = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        var ephemeralSpki = ephemeral.ExportSubjectPublicKeyInfo();
        var keyId = GetKeyId( recipientSpki );
        var key = DeriveKeys( ephemeral, recipient.PublicKey, keyId, ephemeralSpki, out responseKey );
        try
        {
            var all = new byte[KeyIdLength + 2 + ephemeralSpki.Length + 8 + _nonceLength + _tagLength + plain.Length];
            var s = all.AsSpan();
            keyId.CopyTo( s );
            s = s.Slice( KeyIdLength );
            BinaryPrimitives.WriteUInt16BigEndian( s, checked((ushort)ephemeralSpki.Length) );
            ephemeralSpki.CopyTo( s.Slice( 2 ) );
            s = s.Slice( 2 + ephemeralSpki.Length );
            long ticks = utcNow.Ticks;
            BinaryPrimitives.WriteInt64BigEndian( s, ticks );
            var nonce = s.Slice( 8, _nonceLength );
            RandomNumberGenerator.Fill( nonce );
            var tag = s.Slice( 8 + _nonceLength, _tagLength );
            var cipher = s.Slice( 8 + _nonceLength + _tagLength );
            using var aes = new AesGcm( key, _tagLength );
            aes.Encrypt( nonce, plain, cipher, tag, GetAssociatedData( associatedData, ticks ) );
            return all;
        }
        finally
        {
            CryptographicOperations.ZeroMemory( key );
        }
    }

    /// <summary>
    /// Decrypts data encrypted for one of the encryption keys of a local party. The reason of a failure is logged.
    /// </summary>
    /// <param name="logger">Receives the reason of a failure.</param>
    /// <param name="encrypted">The ciphertext.</param>
    /// <param name="findKey">Finds a private encryption key by its identifier (see <see cref="ILocalKeys.FindEncryptionKey"/>).</param>
    /// <param name="associatedData">The context: the one given to <see cref="Encrypt"/>.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="freshness">A ciphertext created before (or after) this time from now is refused.</param>
    /// <param name="plain">The decrypted data on success.</param>
    /// <param name="responseKey">The key with which the answer is encrypted (see <see cref="EncryptResponse"/>).</param>
    /// <returns>True on success.</returns>
    public static bool TryDecrypt( IActivityLineEmitter logger,
                                   ReadOnlySpan<byte> encrypted,
                                   Func<byte[], ECDiffieHellman?> findKey,
                                   ReadOnlySpan<byte> associatedData,
                                   DateTime utcNow,
                                   TimeSpan freshness,
                                   out byte[]? plain,
                                   out byte[]? responseKey )
    {
        plain = null;
        responseKey = null;
        var s = encrypted;
        if( s.Length < KeyIdLength + 2 ) return Malformed( logger );
        var keyId = s.Slice( 0, KeyIdLength ).ToArray();
        int ephemeralLength = BinaryPrimitives.ReadUInt16BigEndian( s.Slice( KeyIdLength ) );
        s = s.Slice( KeyIdLength + 2 );
        if( s.Length < ephemeralLength + 8 + _nonceLength + _tagLength ) return Malformed( logger );
        var ephemeralSpki = s.Slice( 0, ephemeralLength );
        s = s.Slice( ephemeralLength );
        long ticks = BinaryPrimitives.ReadInt64BigEndian( s );
        if( ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks ) return Malformed( logger );
        var created = new DateTime( ticks, DateTimeKind.Utc );
        if( created < utcNow - freshness || created > utcNow + freshness )
        {
            logger.Warn( $"Encrypted data refused: it has been encrypted on {created:O}, out of the {freshness} freshness window." );
            return false;
        }
        var nonce = s.Slice( 8, _nonceLength );
        var tag = s.Slice( 8 + _nonceLength, _tagLength );
        var cipher = s.Slice( 8 + _nonceLength + _tagLength );
        var recipient = findKey( keyId );
        if( recipient == null )
        {
            logger.Warn( "Encrypted data refused: its encryption key is unknown or expired." );
            return false;
        }
        byte[] key;
        try
        {
            using var ephemeral = ECDiffieHellman.Create();
            ephemeral.ImportSubjectPublicKeyInfo( ephemeralSpki, out int read );
            // Unauthenticated input: any curve imports, and the key agreement with another curve throws (an ArgumentException
            // for another size, caught below like any other).
            if( read != ephemeralSpki.Length || ephemeral.KeySize != 256 )
            {
                return Malformed( logger );
            }
            key = DeriveKeys( recipient, ephemeral.PublicKey, keyId, ephemeralSpki, out responseKey );
        }
        catch( Exception ex ) when( ex is CryptographicException or ArgumentException )
        {
            responseKey = null;
            return Malformed( logger );
        }
        var result = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm( key, _tagLength );
            aes.Decrypt( nonce, cipher, tag, result, GetAssociatedData( associatedData, ticks ) );
            plain = result;
            return true;
        }
        catch( AuthenticationTagMismatchException )
        {
            logger.Warn( "Encrypted data refused: it doesn't match its context or it has been altered." );
            CryptographicOperations.ZeroMemory( result );
            responseKey = null;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory( key );
        }
    }

    /// <summary>
    /// Encrypts an answer with the response key of a decrypted message (see <see cref="TryDecrypt"/>).
    /// </summary>
    /// <param name="responseKey">The response key.</param>
    /// <param name="plain">The answer.</param>
    /// <param name="associatedData">The context of the answer.</param>
    /// <returns>The encrypted answer.</returns>
    public static byte[] EncryptResponse( ReadOnlySpan<byte> responseKey, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> associatedData )
    {
        var all = new byte[_nonceLength + _tagLength + plain.Length];
        var nonce = all.AsSpan( 0, _nonceLength );
        RandomNumberGenerator.Fill( nonce );
        using var aes = new AesGcm( responseKey, _tagLength );
        aes.Encrypt( nonce, plain, all.AsSpan( _nonceLength + _tagLength ), all.AsSpan( _nonceLength, _tagLength ), associatedData );
        return all;
    }

    /// <summary>
    /// Decrypts an answer encrypted with the response key of a message (see <see cref="Encrypt"/>). The reason of a failure
    /// is logged.
    /// </summary>
    /// <param name="logger">Receives the reason of a failure.</param>
    /// <param name="responseKey">The response key given by <see cref="Encrypt"/>.</param>
    /// <param name="encrypted">The encrypted answer.</param>
    /// <param name="associatedData">The context of the answer.</param>
    /// <param name="plain">The answer on success.</param>
    /// <returns>True on success.</returns>
    public static bool TryDecryptResponse( IActivityLineEmitter logger, ReadOnlySpan<byte> responseKey, ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> associatedData, out byte[]? plain )
    {
        plain = null;
        if( encrypted.Length < _nonceLength + _tagLength ) return Malformed( logger );
        var result = new byte[encrypted.Length - _nonceLength - _tagLength];
        try
        {
            using var aes = new AesGcm( responseKey, _tagLength );
            aes.Decrypt( encrypted.Slice( 0, _nonceLength ), encrypted.Slice( _nonceLength + _tagLength ), encrypted.Slice( _nonceLength, _tagLength ), result, associatedData );
            plain = result;
            return true;
        }
        catch( AuthenticationTagMismatchException )
        {
            logger.Warn( "Encrypted answer refused: it doesn't match its context or it has been altered." );
            return false;
        }
    }

    // The ephemeral public key is in the info: a ciphertext whose ephemeral point is changed (-E gives the same raw secret)
    // derives other keys and doesn't decrypt.
    static byte[] DeriveKeys( ECDiffieHellman own, ECDiffieHellmanPublicKey other, byte[] keyId, ReadOnlySpan<byte> ephemeralSpki, out byte[] responseKey )
    {
        var shared = own.DeriveRawSecretAgreement( other );
        try
        {
            responseKey = HKDF.DeriveKey( HashAlgorithmName.SHA256, shared, 32, salt: keyId, info: [.. _responseInfo, .. ephemeralSpki] );
            return HKDF.DeriveKey( HashAlgorithmName.SHA256, shared, 32, salt: keyId, info: [.. _encryptionInfo, .. ephemeralSpki] );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( shared );
        }
    }

    static byte[] GetAssociatedData( ReadOnlySpan<byte> context, long ticks )
    {
        var aad = new byte[context.Length + 8];
        context.CopyTo( aad );
        BinaryPrimitives.WriteInt64BigEndian( aad.AsSpan( context.Length ), ticks );
        return aad;
    }

    static bool Malformed( IActivityLineEmitter logger )
    {
        logger.Warn( "Encrypted data refused: it is malformed." );
        return false;
    }
}
