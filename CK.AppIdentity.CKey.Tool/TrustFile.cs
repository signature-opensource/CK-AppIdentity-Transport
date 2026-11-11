using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CK.AppIdentity.CKey.Tool;

/// <summary>
/// The file of an exported trust: the full name of a party and the last events of its key event log (public data), with
/// an expiry, encrypted with AES-GCM under a key derived from a password (PBKDF2-SHA256). Opaque without the password:
/// any change of the file, or a wrong password, fails its reading. The expiry is inside the encrypted data.
/// <para>
/// Layout: <see cref="Magic"/> (8 bytes, also the associated data), the salt (16 bytes), the nonce (12 bytes), the tag
/// (16 bytes), then the ciphertext of a UTF-8 JSON object { "fullName", "expires" (Unix milliseconds), "events" (Base64) }.
/// </para>
/// </summary>
public static class TrustFile
{
    /// <summary>
    /// The first bytes of a trust file (the version is its last character).
    /// </summary>
    public static ReadOnlySpan<byte> Magic => "CKTRUST1"u8;

    /// <summary>
    /// The number of iterations of PBKDF2-SHA256.
    /// </summary>
    public const int Iterations = 600_000;

    /// <summary>
    /// The default lifetime of an exported trust: 1 hour.
    /// </summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours( 1 );

    /// <summary>
    /// The maximal lifetime of an exported trust: 7 days.
    /// </summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays( 7 );

    /// <summary>
    /// The margin accepted on the expiry when reading: the clocks of two machines differ.
    /// </summary>
    public static readonly TimeSpan ClockMargin = TimeSpan.FromMinutes( 5 );

    const int SaltLength = 16;
    const int NonceLength = 12;
    const int TagLength = 16;

    /// <summary>
    /// The content of a trust file.
    /// </summary>
    /// <param name="FullName">The full name of the party.</param>
    /// <param name="Events">The encoded events of its key event log, oldest first.</param>
    /// <param name="Expires">The expiry (UTC).</param>
    public sealed record Content( string FullName, IReadOnlyList<byte[]> Events, DateTime Expires );

    /// <summary>
    /// Generates a password: 100 random bits in Base32 (20 characters), in groups of 4 separated by '-'.
    /// </summary>
    /// <returns>The password.</returns>
    public static string GeneratePassword()
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var b = new StringBuilder( 24 );
        for( int i = 0; i < 20; ++i )
        {
            if( i > 0 && i % 4 == 0 ) b.Append( '-' );
            b.Append( alphabet[RandomNumberGenerator.GetInt32( 32 )] );
        }
        return b.ToString();
    }

    /// <summary>
    /// Parses a duration: a positive number followed by 'm' (minutes), 'h' (hours) or 'd' (days), at most
    /// <see cref="MaxLifetime"/>.
    /// </summary>
    /// <param name="s">The text.</param>
    /// <param name="duration">The duration.</param>
    /// <returns>True on success.</returns>
    public static bool TryParseDuration( string s, out TimeSpan duration )
    {
        duration = default;
        var m = Regex.Match( s.Trim(), "^([0-9]{1,6})([mhd])$" );
        if( !m.Success ) return false;
        int n = int.Parse( m.Groups[1].Value );
        duration = m.Groups[2].Value switch
        {
            "m" => TimeSpan.FromMinutes( n ),
            "h" => TimeSpan.FromHours( n ),
            _ => TimeSpan.FromDays( n )
        };
        return duration > TimeSpan.Zero && duration <= MaxLifetime;
    }

    /// <summary>
    /// Encrypts a trust.
    /// </summary>
    /// <param name="content">The content.</param>
    /// <param name="password">The password.</param>
    /// <returns>The bytes of the file.</returns>
    public static byte[] Encrypt( Content content, string password )
    {
        var plain = new MemoryStream();
        using( var w = new Utf8JsonWriter( plain ) )
        {
            w.WriteStartObject();
            w.WriteString( "fullName", content.FullName );
            w.WriteNumber( "expires", new DateTimeOffset( DateTime.SpecifyKind( content.Expires, DateTimeKind.Utc ) ).ToUnixTimeMilliseconds() );
            w.WriteStartArray( "events" );
            foreach( var e in content.Events ) w.WriteBase64StringValue( e );
            w.WriteEndArray();
            w.WriteEndObject();
        }
        var plainBytes = plain.ToArray();
        var salt = RandomNumberGenerator.GetBytes( SaltLength );
        var nonce = RandomNumberGenerator.GetBytes( NonceLength );
        var tag = new byte[TagLength];
        var cipher = new byte[plainBytes.Length];
        using( var aes = new AesGcm( DeriveKey( password, salt ), TagLength ) )
        {
            aes.Encrypt( nonce, plainBytes, cipher, tag, Magic );
        }
        var file = new MemoryStream();
        file.Write( Magic );
        file.Write( salt );
        file.Write( nonce );
        file.Write( tag );
        file.Write( cipher );
        return file.ToArray();
    }

    /// <summary>
    /// Decrypts a trust file and checks its expiry.
    /// </summary>
    /// <param name="file">The bytes of the file.</param>
    /// <param name="password">The password.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="content">The content on success.</param>
    /// <param name="error">The reason of a failure.</param>
    /// <returns>True on success.</returns>
    public static bool TryDecrypt( ReadOnlySpan<byte> file, string password, DateTime utcNow, out Content? content, out string? error )
    {
        content = null;
        int header = Magic.Length + SaltLength + NonceLength + TagLength;
        if( file.Length <= header || !file.Slice( 0, Magic.Length ).SequenceEqual( Magic ) )
        {
            error = "This is not a trust file exported by ckey.";
            return false;
        }
        var salt = file.Slice( Magic.Length, SaltLength );
        var nonce = file.Slice( Magic.Length + SaltLength, NonceLength );
        var tag = file.Slice( Magic.Length + SaltLength + NonceLength, TagLength );
        var cipher = file.Slice( header );
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm( DeriveKey( password, salt ), TagLength );
            aes.Decrypt( nonce, cipher, tag, plain, Magic );
        }
        catch( AuthenticationTagMismatchException )
        {
            error = "Wrong password, or the file has been modified.";
            return false;
        }
        try
        {
            using var d = JsonDocument.Parse( plain );
            var r = d.RootElement;
            var expires = DateTimeOffset.FromUnixTimeMilliseconds( r.GetProperty( "expires" ).GetInt64() ).UtcDateTime;
            if( expires + ClockMargin < utcNow )
            {
                error = $"The trust file expired at {expires:u}: export it again.";
                return false;
            }
            content = new Content( r.GetProperty( "fullName" ).GetString()!,
                                   r.GetProperty( "events" ).EnumerateArray().Select( e => e.GetBytesFromBase64() ).ToList(),
                                   expires );
            error = null;
            return true;
        }
        catch( Exception ex ) when( ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException )
        {
            error = "The content of the trust file is invalid.";
            return false;
        }
    }

    static byte[] DeriveKey( string password, ReadOnlySpan<byte> salt )
        => Rfc2898DeriveBytes.Pbkdf2( Encoding.UTF8.GetBytes( password ), salt, Iterations, HashAlgorithmName.SHA256, 32 );
}
