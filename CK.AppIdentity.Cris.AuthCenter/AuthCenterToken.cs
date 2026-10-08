using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The token of an Authentication Center: the authentication and its session identifier, signed by the Authentication
/// Center for the <see cref="ICrisAuthCenter.TokenPurpose"/>. It is the Authentication Center's format (with its own
/// version number): only <see cref="CrisAuthCenter.TryReadToken"/> reads it, a client gets the authentication from the
/// session result.
/// <para>
/// The token string is "base64url( len16(data) ‖ data ‖ signature )". The data is:
/// version(1) ‖ audience ‖ sessionId ‖ deviceId ‖ expires ‖ criticalExpires ‖ actual actor ‖ impersonated(1) [‖ actor]
/// where an actor is its identifier, name and level. The audience is the full name of the Authentication Center party: a token
/// of a tenant domain is refused by another one (that has another Authentication Center). The token expires with its signature.
/// </para>
/// </summary>
static class AuthCenterToken
{
    const byte _version = 1;

    internal static string Create( ILocalKeys keys, NormalizedPath audience, string sessionId, AuthenticationInfo info, DateTime expiration )
    {
        var data = Write( audience, sessionId, info );
        var signature = keys.Sign( ICrisAuthCenter.TokenPurpose, data, expiration );
        var encoded = signature.Encoded.Span;
        var all = new byte[2 + data.Length + encoded.Length];
        BinaryPrimitives.WriteUInt16BigEndian( all, checked((ushort)data.Length) );
        data.CopyTo( all.AsSpan( 2 ) );
        encoded.CopyTo( all.AsSpan( 2 + data.Length ) );
        return Base64Url.EncodeToString( all );
    }

    static byte[] Write( NormalizedPath audience, string sessionId, AuthenticationInfo info )
    {
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( _version );
            w.Write( audience.Path );
            w.Write( sessionId );
            w.Write( info.DeviceId );
            w.Write( info.Expires?.Ticks ?? 0L );
            w.Write( info.CriticalExpires?.Ticks ?? 0L );
            WriteActor( w, info.UnsafeActualActor );
            w.Write( info.IsImpersonated );
            if( info.IsImpersonated ) WriteActor( w, info.UnsafeActor );
        }
        return m.ToArray();

        static void WriteActor( BinaryWriter w, ActorInfo a )
        {
            w.Write( a.ActorId );
            w.Write( a.ActorName );
            w.Write( (byte)a.Level );
        }
    }

    internal static bool TryRead( IActivityLineEmitter logger,
                                  ICrisAuthCenter center,
                                  NormalizedPath audience,
                                  string token,
                                  DateTime utcNow,
                                  [NotNullWhen( true )] out AuthenticationInfo? info,
                                  [NotNullWhen( true )] out string? sessionId )
    {
        info = null;
        sessionId = null;
        byte[] all;
        try
        {
            all = Base64Url.DecodeFromChars( token );
        }
        catch( FormatException )
        {
            logger.Warn( "Token refused: it is malformed." );
            return false;
        }
        if( all.Length < 2 ) return Malformed( logger );
        int dataLength = BinaryPrimitives.ReadUInt16BigEndian( all );
        if( all.Length < 2 + dataLength ) return Malformed( logger );
        var data = all.AsSpan( 2, dataLength );
        if( !ApplicationSignature.TryRead( all.AsSpan( 2 + dataLength ), out var signature ) ) return Malformed( logger );
        if( signature.Expiration <= utcNow )
        {
            logger.Warn( $"Token refused: it expired at {signature.Expiration:O}." );
            return false;
        }
        // The signature first: nothing is read from unverified data.
        if( !center.Verify( logger, data, signature ) ) return false;
        try
        {
            using var r = new BinaryReader( new MemoryStream( all, 2, dataLength, writable: false ), Encoding.UTF8 );
            var version = r.ReadByte();
            if( version != _version )
            {
                logger.Warn( $"Token refused: unknown version {version}." );
                return false;
            }
            var tokenAudience = r.ReadString();
            if( tokenAudience != audience.Path )
            {
                logger.Warn( $"Token refused: it has been issued for '{tokenAudience}', not for '{audience}'." );
                return false;
            }
            sessionId = r.ReadString();
            var deviceId = r.ReadString();
            var expires = ReadDate( r );
            var criticalExpires = ReadDate( r );
            var actual = ReadActor( r );
            var actor = r.ReadBoolean() ? ReadActor( r ) : actual;
            if( r.BaseStream.Position != r.BaseStream.Length ) return Malformed( logger );
            // The token expires with its signature: the authentication cannot outlive it.
            var end = signature.Expiration;
            expires = expires.HasValue && expires.Value > end ? end : expires;
            criticalExpires = criticalExpires.HasValue && criticalExpires.Value > end ? end : criticalExpires;
            info = AuthenticationInfo.Create( actual, actor, expires, criticalExpires, deviceId, utcNow );
            return true;
        }
        catch( Exception ex ) when( ex is EndOfStreamException or ArgumentException or FormatException )
        {
            sessionId = null;
            return Malformed( logger );
        }

        static DateTime? ReadDate( BinaryReader r )
        {
            var t = r.ReadInt64();
            return t == 0 ? null : new DateTime( t, DateTimeKind.Utc );
        }

        static ActorInfo ReadActor( BinaryReader r )
        {
            var id = r.ReadInt32();
            var name = r.ReadString();
            var level = (AuthLevel)r.ReadByte();
            return new ActorInfo( id, name, level );
        }
    }

    static bool Malformed( IActivityLineEmitter logger )
    {
        logger.Warn( "Token refused: it is malformed." );
        return false;
    }
}
