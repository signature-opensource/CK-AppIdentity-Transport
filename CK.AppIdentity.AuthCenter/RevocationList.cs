using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The revocation list of an Authentication Center: the revoked identities (see <see cref="RevocationEntry"/>), a
/// sequence number (a newer list replaces an older one) and its time, signed by the Authentication Center
/// (<see cref="Purpose"/>). It travels by any path: it is verified with the keys of the Authentication Center (pinned or
/// anchored). A hop can withhold it, not forge it.
/// </summary>
public sealed class RevocationList
{
    /// <summary>
    /// The purpose of the signature of a list by the Authentication Center.
    /// </summary>
    public const string Purpose = "CK.AuthCenter.RevocationList";

    const byte Version = 0;

    readonly byte[] _data;

    RevocationList( int seq, DateTime time, IReadOnlyList<RevocationEntry> entries, byte[] data, ApplicationSignature signature )
    {
        Seq = seq;
        Time = time;
        Entries = entries;
        _data = data;
        Signature = signature;
    }

    /// <summary>
    /// Gets the sequence number: a list replaces the ones with a smaller one.
    /// </summary>
    public int Seq { get; }

    /// <summary>
    /// Gets when the list has been signed.
    /// </summary>
    public DateTime Time { get; }

    /// <summary>
    /// Gets the revoked identities.
    /// </summary>
    public IReadOnlyList<RevocationEntry> Entries { get; }

    /// <summary>
    /// Gets the signature of the Authentication Center.
    /// </summary>
    public ApplicationSignature Signature { get; }

    /// <summary>
    /// Gets the signed data.
    /// </summary>
    public ReadOnlySpan<byte> SignedData => _data;

    /// <summary>
    /// Creates and signs a list.
    /// </summary>
    /// <param name="keys">The keys of the Authentication Center.</param>
    /// <param name="seq">The sequence number.</param>
    /// <param name="entries">The revoked identities.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The signed list.</returns>
    public static RevocationList Create( ILocalKeys keys, int seq, IReadOnlyList<RevocationEntry> entries, DateTime utcNow )
    {
        Throw.CheckNotNullArgument( keys );
        Throw.CheckArgument( seq > 0 );
        var data = GetSignedData( seq, utcNow, entries );
        var signature = keys.Sign( Purpose, data, utcNow.AddDays( keys.MaxSignatureDays ) );
        return new RevocationList( seq, utcNow, entries, data, signature );
    }

    static byte[] GetSignedData( int seq, DateTime time, IReadOnlyList<RevocationEntry> entries )
    {
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( Version );
            w.Write( seq );
            w.Write( time.Ticks );
            w.Write( entries.Count );
            foreach( var e in entries )
            {
                w.Write( e.FullName );
                w.Write( e.Identity.Span );
                w.Write( e.RevokedAt.Ticks );
                w.Write( e.NameBanned );
            }
        }
        return m.ToArray();
    }

    /// <summary>
    /// Encodes this list: the length of the signed data (4 bytes), the signed data, then the signature.
    /// </summary>
    /// <returns>The encoded list.</returns>
    public byte[] Encode()
    {
        var s = Signature.Encoded.Span;
        var r = new byte[4 + _data.Length + s.Length];
        BinaryPrimitives.WriteInt32LittleEndian( r, _data.Length );
        _data.CopyTo( r, 4 );
        s.CopyTo( r.AsSpan( 4 + _data.Length ) );
        return r;
    }

    /// <summary>
    /// Decodes a list (its signature is not verified here).
    /// </summary>
    /// <param name="encoded">The encoded list.</param>
    /// <param name="list">The list.</param>
    /// <returns>True on success, false when the data is not an encoded list.</returns>
    public static bool TryDecode( ReadOnlySpan<byte> encoded, out RevocationList? list )
    {
        list = null;
        if( encoded.Length < 4 ) return false;
        int length = BinaryPrimitives.ReadInt32LittleEndian( encoded );
        if( length <= 0 || length > encoded.Length - 4 ) return false;
        var data = encoded.Slice( 4, length ).ToArray();
        if( !ApplicationSignature.TryRead( encoded.Slice( 4 + length ), out var signature ) ) return false;
        try
        {
            using var r = new BinaryReader( new MemoryStream( data, writable: false ), Encoding.UTF8 );
            if( r.ReadByte() != Version ) return false;
            int seq = r.ReadInt32();
            var time = new DateTime( r.ReadInt64(), DateTimeKind.Utc );
            int count = r.ReadInt32();
            if( seq <= 0 || count < 0 || count > 100_000 ) return false;
            var entries = new RevocationEntry[count];
            for( int i = 0; i < count; ++i )
            {
                var name = r.ReadString();
                var identity = r.ReadBytes( KeyEvent.HashSize );
                if( identity.Length != KeyEvent.HashSize || name.Length == 0 ) return false;
                entries[i] = new RevocationEntry( name, identity, new DateTime( r.ReadInt64(), DateTimeKind.Utc ), r.ReadBoolean() );
            }
            if( r.BaseStream.Position != data.Length ) return false;
            list = new RevocationList( seq, time, entries, data, signature );
            return true;
        }
        catch( Exception ex ) when( ex is EndOfStreamException or ArgumentException or IOException )
        {
            return false;
        }
    }

    /// <inheritdoc />
    public override string ToString() => $"Revocation list #{Seq} ({Entries.Count} entries, {Time:O})";
}
