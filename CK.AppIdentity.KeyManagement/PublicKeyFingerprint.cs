using System;
using System.Security.Cryptography;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Computes the <see cref="IPublicKeyData.Fingerprint"/>.
/// </summary>
public static class PublicKeyFingerprint
{
    /// <summary>
    /// Number of bytes of the SHA-256 that are kept: 20 bytes is 160 bits, which is far more
    /// than enough against a second-preimage search and gives 32 Base32 characters.
    /// </summary>
    public const int ByteLength = 20;

    /// <summary>
    /// Length of the <see cref="Compute(ReadOnlySpan{byte})"/> result, separators included.
    /// </summary>
    public const int Length = 32 + 7;

    // RFC 4648 Base32 without the padding, minus 'I', 'L', 'O' and 'U' would be nicer to read
    // but a non standard alphabet is not worth the surprise: this is the standard one.
    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>
    /// Computes the fingerprint of a SubjectPublicKeyInfo raw data.
    /// </summary>
    /// <param name="publicKeyRawData">The raw public key data.</param>
    /// <returns>The fingerprint.</returns>
    public static string Compute( ReadOnlySpan<byte> publicKeyRawData )
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData( publicKeyRawData, hash );
        return ToBase32( hash.Slice( 0, ByteLength ) );
    }

    static string ToBase32( ReadOnlySpan<byte> bytes )
    {
        // 20 bytes = 160 bits = exactly 32 Base32 characters: no padding is ever needed here.
        Span<char> chars = stackalloc char[Length];
        int iChar = 0;
        int nChars = 0;
        int bitBuffer = 0;
        int bitCount = 0;
        foreach( var b in bytes )
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitCount += 8;
            while( bitCount >= 5 )
            {
                bitCount -= 5;
                if( nChars > 0 && nChars % 4 == 0 ) chars[iChar++] = '-';
                chars[iChar++] = Alphabet[(bitBuffer >> bitCount) & 0x1F];
                ++nChars;
            }
        }
        return new string( chars.Slice( 0, iChar ) );
    }
}
