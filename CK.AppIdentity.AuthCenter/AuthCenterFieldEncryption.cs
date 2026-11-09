using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The encryption of the sensitive fields of the commands that a remote sends to its Authentication Center, with the
/// encryption key of the Authentication Center's party (see <see cref="PartyEncryption"/>: it publishes it in its
/// description).
/// <para>
/// The associated data binds the ciphertext to its context (the Authentication Center, the remote, the command type and
/// the property): it cannot be moved to another field, command or remote, and an old one is refused (see <see cref="Freshness"/>).
/// </para>
/// <para>
/// A field is a string, so its ciphertext is too: "ckenc1:" + base64url( the <see cref="PartyEncryption"/> ciphertext of the
/// UTF-8 value ).
/// </para>
/// </summary>
static class AuthCenterFieldEncryption
{
    internal const string Prefix = "ckenc1:";

    /// <summary>
    /// A ciphertext older (or newer) than this is refused.
    /// </summary>
    internal static readonly TimeSpan Freshness = TimeSpan.FromMinutes( 5 );

    /// <summary>
    /// Gets the context of a field: the Authentication Center, the remote that sends it, the command type and the property.
    /// </summary>
    internal static byte[] GetContext( NormalizedPath authCenter, NormalizedPath remote, string pocoName, string propertyName )
        => Encoding.UTF8.GetBytes( $"{authCenter.Path}\n{remote.Path}\n{pocoName}\n{propertyName}" );

    internal static string Encrypt( ReadOnlySpan<byte> recipientSpki, string clear, ReadOnlySpan<byte> context, DateTime utcNow )
    {
        var plain = Encoding.UTF8.GetBytes( clear );
        try
        {
            return Prefix + Base64Url.EncodeToString( PartyEncryption.Encrypt( recipientSpki, plain, context, utcNow, out _ ) );
        }
        finally
        {
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
        byte[] encrypted;
        try
        {
            encrypted = Base64Url.DecodeFromChars( value.AsSpan( Prefix.Length ) );
        }
        catch( FormatException )
        {
            logger.Warn( "Sensitive field refused: it is malformed." );
            return false;
        }
        if( !PartyEncryption.TryDecrypt( logger, encrypted, findKey, context, utcNow, Freshness, out var plain, out _ ) )
        {
            return false;
        }
        try
        {
            clear = Encoding.UTF8.GetString( plain! );
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory( plain );
        }
    }
}
