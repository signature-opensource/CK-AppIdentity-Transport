using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The seal of the command of a routed command (<see cref="CK.AppIdentity.Cris.IPartyRoutedCommand.SealedCommand"/>) that
/// carries a user's proof: the party that opened the user's session (the token's <see cref="AuthCenterTokenContent.SessionParty"/>)
/// signs a header and the digest of the exact bytes of the command. The hops can't alter the command, re-target it, nor
/// use the proof for another command: only the session party may present a proof at the Critical level, and through hops
/// it does so by this signature.
/// <para>
/// The header is: version(1) ‖ destination ‖ tokenDigest(32) ‖ ticks(8) ‖ nonce(16) ‖ encrypted(1), where the destination
/// is the full name of the party that executes the command, the token digest the SHA-256 of the token's UTF-8 bytes (the
/// seal is bound to the proof it travels with), the ticks the creation time (Utc) and the nonce random (a seal is used
/// once). The encrypted flag is reserved for the encryption of the command (not supported yet: a sealed command is in
/// clear). The signature (<see cref="Purpose"/>) covers the header followed by the SHA-256 of the command's bytes: the
/// Authentication Center verifies it without the command.
/// </para>
/// </summary>
public static class RoutedCommandSeal
{
    /// <summary>
    /// The purpose of the signature of a seal.
    /// </summary>
    public const string Purpose = "CK.AuthCenter.RoutedCommand";

    /// <summary>
    /// The lifetime of a seal: 5 minutes after its creation (its signature expires then).
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes( 5 );

    /// <summary>
    /// The tolerated clock offset between the session party and the verifier: 1 minute.
    /// </summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes( 1 );

    const byte _version = 0;
    const int _digestLength = 32;
    const int _nonceLength = 16;

    /// <summary>
    /// Gets the digest of the bytes of a sealed command (SHA-256).
    /// </summary>
    /// <param name="sealedCommand">The bytes of the command.</param>
    /// <returns>The digest.</returns>
    public static byte[] GetPayloadDigest( ReadOnlySpan<byte> sealedCommand ) => SHA256.HashData( sealedCommand );

    /// <summary>
    /// Creates the seal of a command: its header and its signature by the local party (the session party).
    /// </summary>
    /// <param name="keys">The keys of the local party.</param>
    /// <param name="destination">The full name of the party that executes the command.</param>
    /// <param name="token">The user's token that travels with the command.</param>
    /// <param name="sealedCommand">The bytes of the command.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The header and the encoded signature.</returns>
    internal static (byte[] Header, byte[] Signature) Create( ILocalKeys keys, string destination, string token, ReadOnlySpan<byte> sealedCommand, DateTime utcNow )
    {
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( _version );
            w.Write( destination );
            w.Write( GetTokenDigest( token ) );
            w.Write( utcNow.Ticks );
            w.Write( RandomNumberGenerator.GetBytes( _nonceLength ) );
            w.Write( false );
        }
        var header = m.ToArray();
        var signature = keys.Sign( Purpose, GetSignedData( header, GetPayloadDigest( sealedCommand ) ), utcNow + Lifetime );
        return (header, signature.Encoded.ToArray());
    }

    /// <summary>
    /// Gets the data covered by the signature: the header followed by the digest of the command.
    /// </summary>
    internal static byte[] GetSignedData( ReadOnlySpan<byte> header, ReadOnlySpan<byte> payloadDigest )
    {
        var data = new byte[header.Length + payloadDigest.Length];
        header.CopyTo( data );
        payloadDigest.CopyTo( data.AsSpan( header.Length ) );
        return data;
    }

    /// <summary>
    /// Reads a header and checks it: the version, the destination, the token and the time. The reason of a refusal is
    /// logged. The signature and the nonce are checked by the caller.
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="header">The header.</param>
    /// <param name="expectedDestination">The full name of the party that executes the command.</param>
    /// <param name="token">The user's token that travels with the command.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="nonce">The nonce of the seal.</param>
    /// <param name="created">The creation time of the seal.</param>
    /// <returns>True if the header is valid.</returns>
    internal static bool CheckHeader( IActivityLineEmitter logger,
                                      ReadOnlySpan<byte> header,
                                      string expectedDestination,
                                      string token,
                                      DateTime utcNow,
                                      out string? nonce,
                                      out DateTime created )
    {
        nonce = null;
        created = default;
        string destination;
        byte[] tokenDigest;
        long ticks;
        bool encrypted;
        try
        {
            using var r = new BinaryReader( new MemoryStream( header.ToArray(), writable: false ), Encoding.UTF8 );
            var version = r.ReadByte();
            if( version != _version )
            {
                logger.Warn( $"Routed command seal refused: unknown version {version}." );
                return false;
            }
            destination = r.ReadString();
            tokenDigest = r.ReadBytes( _digestLength );
            ticks = r.ReadInt64();
            var n = r.ReadBytes( _nonceLength );
            encrypted = r.ReadBoolean();
            if( tokenDigest.Length != _digestLength
                || n.Length != _nonceLength
                || r.BaseStream.Position != r.BaseStream.Length
                || ticks < DateTime.MinValue.Ticks
                || ticks > DateTime.MaxValue.Ticks )
            {
                return Malformed( logger );
            }
            nonce = Convert.ToHexString( n );
        }
        catch( Exception ex ) when( ex is EndOfStreamException or FormatException or ArgumentException )
        {
            return Malformed( logger );
        }
        if( encrypted )
        {
            logger.Warn( "Routed command seal refused: an encrypted command is not supported." );
            return false;
        }
        if( destination != expectedDestination )
        {
            logger.Warn( $"Routed command seal refused: it has been made for '{destination}', not for '{expectedDestination}'." );
            return false;
        }
        if( !CryptographicOperations.FixedTimeEquals( tokenDigest, GetTokenDigest( token ) ) )
        {
            logger.Warn( "Routed command seal refused: it has been made for another user's proof." );
            return false;
        }
        created = new DateTime( ticks, DateTimeKind.Utc );
        if( created > utcNow + ClockSkew || created < utcNow - Lifetime - ClockSkew )
        {
            logger.Warn( $"Routed command seal refused: it has been made on {created:O}, out of its {Lifetime} lifetime." );
            return false;
        }
        return true;
    }

    static byte[] GetTokenDigest( string token ) => SHA256.HashData( Encoding.UTF8.GetBytes( token ) );

    static bool Malformed( IActivityLineEmitter logger )
    {
        logger.Warn( "Routed command seal refused: it is malformed." );
        return false;
    }
}

/// <summary>
/// The seal of a routed command presented for verification (see <see cref="RoutedCommandSeal"/>): what the Authentication
/// Center needs, without the command itself.
/// </summary>
/// <param name="Header">The header of the seal.</param>
/// <param name="PayloadDigest">The digest of the bytes of the command (see <see cref="RoutedCommandSeal.GetPayloadDigest"/>).</param>
/// <param name="Signature">The encoded signature of the seal.</param>
public sealed record RoutedProofSeal( byte[] Header, byte[] PayloadDigest, byte[] Signature );
