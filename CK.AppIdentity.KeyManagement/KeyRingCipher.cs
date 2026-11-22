using CK.Core;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The encryption of the key files of the DataProtection key ring by a 256-bit content key (see <see cref="KeyRingStore"/>):
/// AES-256-GCM, a random nonce per file. Where the content key comes from is the business of the encryptor: the secret
/// "KeyManagement:KeyRingKey" itself, or a fresh key wrapped by a key of a CNG provider (CK.AppIdentity.KeyManagement.Cng).
/// </summary>
public static class KeyRingCipher
{
    /// <summary>
    /// The length of a content key: 32 bytes (AES-256).
    /// </summary>
    public const int KeyLength = 32;

    const int NonceLength = 12;
    const int TagLength = 16;
    static readonly byte[] _associatedData = "CK.AppIdentity.KeyRing"u8.ToArray();

    /// <summary>
    /// Encrypts an element of the key ring.
    /// </summary>
    /// <param name="element">The element to encrypt.</param>
    /// <param name="key">The content key (<see cref="KeyLength"/> bytes).</param>
    /// <returns>The base64 of the nonce, the cipher text and the tag.</returns>
    public static string Seal( XElement element, ReadOnlySpan<byte> key )
    {
        Throw.CheckNotNullArgument( element );
        Throw.CheckArgument( key.Length == KeyLength );
        byte[] plain;
        using( var m = new MemoryStream() )
        {
            element.Save( m, SaveOptions.DisableFormatting );
            plain = m.ToArray();
        }
        try
        {
            var result = new byte[NonceLength + plain.Length + TagLength];
            var nonce = result.AsSpan( 0, NonceLength );
            RandomNumberGenerator.Fill( nonce );
            using var aes = new AesGcm( key, TagLength );
            aes.Encrypt( nonce, plain, result.AsSpan( NonceLength, plain.Length ), result.AsSpan( NonceLength + plain.Length ), _associatedData );
            return Convert.ToBase64String( result );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( plain );
        }
    }

    /// <summary>
    /// Decrypts an element of the key ring encrypted by <see cref="Seal(XElement, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="value">The base64 of the nonce, the cipher text and the tag.</param>
    /// <param name="key">The content key (<see cref="KeyLength"/> bytes).</param>
    /// <returns>The element.</returns>
    public static XElement Open( string value, ReadOnlySpan<byte> key )
    {
        Throw.CheckNotNullArgument( value );
        Throw.CheckArgument( key.Length == KeyLength );
        var data = Convert.FromBase64String( value );
        if( data.Length < NonceLength + TagLength ) throw new CryptographicException( "Invalid encrypted key ring element." );
        var plain = new byte[data.Length - NonceLength - TagLength];
        try
        {
            using var aes = new AesGcm( key, TagLength );
            aes.Decrypt( data.AsSpan( 0, NonceLength ), data.AsSpan( NonceLength, plain.Length ), data.AsSpan( NonceLength + plain.Length ), plain, _associatedData );
            using var m = new MemoryStream( plain, writable: false );
            return XElement.Load( m );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( plain );
        }
    }
}
