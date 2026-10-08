using CK.Core;
using CK.Cris;
using System;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The encryption of the sensitive fields of the relayed session commands, for the Authentication Center.
/// <para>
/// HPKE-like: an ephemeral ECDH P-256 key agreement with the Authentication Center's encryption key, HKDF-SHA256, then
/// AES-256-GCM. The associated data binds the ciphertext to its context (the Authentication Center, the front, the command
/// type and the property) and to its creation time: it cannot be moved to another field, command or front, and an old one
/// is refused.
/// </para>
/// <para>
/// A ciphertext is "ckenc1:" + base64url( keyId(8) ‖ len16(ephemeral SPKI) ‖ ephemeral SPKI ‖ ticks(8) ‖ nonce(12) ‖ tag(16) ‖ cipher ).
/// </para>
/// </summary>
static class AuthCenterFieldEncryption
{
    internal const string Prefix = "ckenc1:";
    internal const int KeyIdLength = 8;

    /// <summary>
    /// A ciphertext older (or newer) than this is refused.
    /// </summary>
    internal static readonly TimeSpan Freshness = TimeSpan.FromMinutes( 5 );

    static readonly byte[] _info = "CK.AuthCenter.Field.v1"u8.ToArray();
    static readonly ConcurrentDictionary<Type, PropertyInfo[]?> _sensitiveFields = new();

    internal static byte[] GetKeyId( ReadOnlySpan<byte> spki ) => SHA256.HashData( spki ).AsSpan( 0, KeyIdLength ).ToArray();

    /// <summary>
    /// Gets the context of a field: the Authentication Center, the front, the command type and the property.
    /// </summary>
    internal static byte[] GetContext( NormalizedPath authCenter, NormalizedPath front, string pocoName, string propertyName )
        => Encoding.UTF8.GetBytes( $"{authCenter.Path}\n{front.Path}\n{pocoName}\n{propertyName}" );

    /// <summary>
    /// Gets the [Sensitive] properties of a command type. Null when a sensitive property is not a string: such a command
    /// cannot be relayed.
    /// </summary>
    internal static PropertyInfo[]? GetSensitiveFields( Type commandType )
    {
        return _sensitiveFields.GetOrAdd( commandType, static t =>
        {
            var all = t.GetInterfaces()
                       .SelectMany( i => i.GetProperties() )
                       .Where( p => p.IsDefined( typeof( SensitiveAttribute ), inherit: true ) )
                       .GroupBy( p => p.Name )
                       .Select( g => g.First() )
                       .ToArray();
            return all.All( p => p.PropertyType == typeof( string ) && p.CanWrite ) ? all : null;
        } );
    }

    internal static string Encrypt( ReadOnlySpan<byte> recipientSpki, string clear, ReadOnlySpan<byte> context, DateTime utcNow )
    {
        using var recipient = ECDiffieHellman.Create();
        recipient.ImportSubjectPublicKeyInfo( recipientSpki, out _ );
        using var ephemeral = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        var ephemeralSpki = ephemeral.ExportSubjectPublicKeyInfo();
        var keyId = GetKeyId( recipientSpki );
        var key = DeriveKey( ephemeral, recipient.PublicKey, keyId );
        var plain = Encoding.UTF8.GetBytes( clear );
        try
        {
            var all = new byte[KeyIdLength + 2 + ephemeralSpki.Length + 8 + 12 + 16 + plain.Length];
            var s = all.AsSpan();
            keyId.CopyTo( s );
            s = s.Slice( KeyIdLength );
            BinaryPrimitives.WriteUInt16BigEndian( s, checked((ushort)ephemeralSpki.Length) );
            ephemeralSpki.CopyTo( s.Slice( 2 ) );
            s = s.Slice( 2 + ephemeralSpki.Length );
            long ticks = utcNow.Ticks;
            BinaryPrimitives.WriteInt64BigEndian( s, ticks );
            var nonce = s.Slice( 8, 12 );
            RandomNumberGenerator.Fill( nonce );
            var tag = s.Slice( 20, 16 );
            var cipher = s.Slice( 36 );
            using var aes = new AesGcm( key, 16 );
            aes.Encrypt( nonce, plain, cipher, tag, GetAssociatedData( context, ticks ) );
            return Prefix + Base64Url.EncodeToString( all );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( key );
            CryptographicOperations.ZeroMemory( plain );
        }
    }

    /// <summary>
    /// Decrypts a field. The reason of a failure is logged.
    /// </summary>
    internal static bool TryDecrypt( IActivityLineEmitter logger,
                                     string value,
                                     Func<byte[], ECDiffieHellman?> findKey,
                                     ReadOnlySpan<byte> context,
                                     DateTime utcNow,
                                     out string? clear )
    {
        clear = null;
        if( !value.StartsWith( Prefix, StringComparison.Ordinal ) )
        {
            logger.Warn( "Sensitive field refused: it is not encrypted for the AuthCenter." );
            return false;
        }
        byte[] all;
        try
        {
            all = Base64Url.DecodeFromChars( value.AsSpan( Prefix.Length ) );
        }
        catch( FormatException )
        {
            return Malformed( logger );
        }
        var s = all.AsSpan();
        if( s.Length < KeyIdLength + 2 ) return Malformed( logger );
        var keyId = s.Slice( 0, KeyIdLength ).ToArray();
        int ephemeralLength = BinaryPrimitives.ReadUInt16BigEndian( s.Slice( KeyIdLength ) );
        s = s.Slice( KeyIdLength + 2 );
        if( s.Length < ephemeralLength + 8 + 12 + 16 ) return Malformed( logger );
        var ephemeralSpki = s.Slice( 0, ephemeralLength );
        s = s.Slice( ephemeralLength );
        long ticks = BinaryPrimitives.ReadInt64BigEndian( s );
        if( ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks ) return Malformed( logger );
        var created = new DateTime( ticks, DateTimeKind.Utc );
        if( created < utcNow - Freshness || created > utcNow + Freshness )
        {
            logger.Warn( $"Sensitive field refused: it has been encrypted on {created:O}, out of the {Freshness} freshness window." );
            return false;
        }
        var nonce = s.Slice( 8, 12 );
        var tag = s.Slice( 20, 16 );
        var cipher = s.Slice( 36 );
        var recipient = findKey( keyId );
        if( recipient == null )
        {
            logger.Warn( "Sensitive field refused: its encryption key is unknown or expired." );
            return false;
        }
        byte[] key;
        try
        {
            using var ephemeral = ECDiffieHellman.Create();
            ephemeral.ImportSubjectPublicKeyInfo( ephemeralSpki, out _ );
            key = DeriveKey( recipient, ephemeral.PublicKey, keyId );
        }
        catch( CryptographicException )
        {
            return Malformed( logger );
        }
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm( key, 16 );
            aes.Decrypt( nonce, cipher, tag, plain, GetAssociatedData( context, ticks ) );
            clear = Encoding.UTF8.GetString( plain );
            return true;
        }
        catch( AuthenticationTagMismatchException )
        {
            logger.Warn( "Sensitive field refused: it doesn't match its context (another field, command or front) or it has been altered." );
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory( key );
            CryptographicOperations.ZeroMemory( plain );
        }
    }

    static byte[] DeriveKey( ECDiffieHellman own, ECDiffieHellmanPublicKey other, byte[] keyId )
    {
        var shared = own.DeriveRawSecretAgreement( other );
        try
        {
            return HKDF.DeriveKey( HashAlgorithmName.SHA256, shared, 32, salt: keyId, info: _info );
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
        logger.Warn( "Sensitive field refused: it is malformed." );
        return false;
    }
}
