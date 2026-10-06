using CK.Core;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// One event of a party's key event log: it reveals the identity key of <see cref="Seq"/> and commits
/// to the next one.
/// <para>
/// The right to rotate belongs to the key a party committed to beforehand, never to the key in use:
/// an event is accepted after event <c>s</c> only if the hash of the key it reveals is the
/// <see cref="NextCommit"/> of event <c>s</c>, and it is signed by that revealed key. A thief holding
/// the current key can sign with it, but cannot produce the next event.
/// </para>
/// <para>
/// An event carries no party name: the name is supplied by whoever reads it and is part of what is
/// signed, so that an event of one party can never be accepted into the chain of another.
/// </para>
/// </summary>
public sealed class KeyEvent
{
    /// <summary>
    /// Size of <see cref="NextCommit"/>, <see cref="PrevDigest"/> and <see cref="Digest"/>: a SHA-256.
    /// </summary>
    public const int HashSize = 32;

    /// <summary>
    /// Upper bound of an encoded event. An identity key is a P-256 SPKI (91 bytes) and its signature
    /// 64 bytes, so an actual event is about 240 bytes: this bounds what a peer can make us parse.
    /// </summary>
    public const int MaxEncodedSize = 4 + 8 + 2 + ILocalKeys.MaxPublicKeySize + HashSize + HashSize + 1 + 255;

    // Domain separation: the identity key signs other things (derived credentials), and nothing it
    // signs for one purpose may be replayable as another.
    static ReadOnlySpan<byte> DomainTag => "CK.AppIdentity.KEL/0"u8;

    readonly byte[] _spki;
    readonly byte[] _nextCommit;
    readonly byte[] _prevDigest;
    readonly byte[] _signature;
    readonly byte[] _encoded;
    readonly DateTime _timeName;
    readonly int _seq;
    // One reference, written and read whole, so that a reader never pairs a digest with the wrong name.
    sealed record DigestCache( string Name, byte[] Digest );
    DigestCache? _digest;

    KeyEvent( int seq, DateTime timeName, byte[] spki, byte[] nextCommit, byte[] prevDigest, byte[] signature )
    {
        _seq = seq;
        _timeName = timeName;
        _spki = spki;
        _nextCommit = nextCommit;
        _prevDigest = prevDigest;
        _signature = signature;
        _encoded = Encode();
    }

    /// <summary>
    /// Gets the position of this event in the log. The inception is 0.
    /// </summary>
    public int Seq => _seq;

    /// <summary>
    /// Gets the creation time of the key this event reveals (UTC).
    /// </summary>
    public DateTime TimeName => _timeName;

    /// <summary>
    /// Gets the SubjectPublicKeyInfo of the identity key this event reveals.
    /// </summary>
    public ReadOnlyMemory<byte> Spki => _spki;

    /// <summary>
    /// Gets the SHA-256 of the next identity key's SPKI, or 32 zero bytes when this event
    /// <see cref="IsAbandonment">abandons</see> the identity.
    /// </summary>
    public ReadOnlyMemory<byte> NextCommit => _nextCommit;

    /// <summary>
    /// Gets the <see cref="GetDigest">digest</see> of the previous event, or 32 zero bytes for the inception.
    /// </summary>
    public ReadOnlyMemory<byte> PrevDigest => _prevDigest;

    /// <summary>
    /// Gets the signature, by the key this event reveals.
    /// </summary>
    public ReadOnlyMemory<byte> Signature => _signature;

    /// <summary>
    /// Gets whether this is the first event of a log.
    /// </summary>
    public bool IsInception => _seq == 0;

    /// <summary>
    /// Gets whether this event ends the identity: there is no next key, so nothing can follow it.
    /// SHA-256 cannot produce 32 zero bytes in practice, which is what makes the value free to reserve.
    /// </summary>
    public bool IsAbandonment => _nextCommit.AsSpan().IndexOfAnyExcept( (byte)0 ) < 0;

    /// <summary>
    /// Gets the encoded form of this event, as it is transmitted and stored.
    /// </summary>
    public ReadOnlyMemory<byte> Encoded => _encoded;

    /// <summary>
    /// Gets the digest that identifies this event: the SHA-256 of what is signed, which includes the
    /// party name.
    /// <para>
    /// The signature is deliberately <b>not</b> covered. ECDSA signatures are malleable — whoever
    /// relays an event can turn a valid signature into another valid one for the same content — so a
    /// digest over the signature would let a relay change an event's identity without changing the
    /// event, and make an honest log look like a fork.
    /// </para>
    /// </summary>
    /// <param name="fullName">The full name of the party whose log this is.</param>
    /// <returns>The 32-byte digest.</returns>
    public ReadOnlyMemory<byte> GetDigest( string fullName )
    {
        // One party reads one log: a cache keyed by the last name asked is enough.
        var c = _digest;
        if( c == null || c.Name != fullName )
        {
            var d = new byte[HashSize];
            SHA256.HashData( GetSignedPayload( fullName ), d );
            _digest = c = new DigestCache( fullName, d );
        }
        return c.Digest;
    }

    /// <summary>
    /// Computes the commitment to an identity key: the SHA-256 of its SPKI.
    /// </summary>
    /// <param name="spki">The SubjectPublicKeyInfo of the key.</param>
    /// <returns>The 32-byte commitment.</returns>
    public static byte[] ComputeCommit( ReadOnlySpan<byte> spki ) => SHA256.HashData( spki );

    /// <summary>
    /// Gets whether this event commits to the key whose SPKI is <paramref name="spki"/>.
    /// </summary>
    /// <param name="spki">A SubjectPublicKeyInfo.</param>
    /// <returns>True if <paramref name="spki"/> is the committed next key.</returns>
    public bool CommitsTo( ReadOnlySpan<byte> spki )
    {
        if( IsAbandonment ) return false;
        Span<byte> h = stackalloc byte[HashSize];
        SHA256.HashData( spki, h );
        return CryptographicOperations.FixedTimeEquals( h, _nextCommit );
    }

    /// <summary>
    /// Creates and signs an event.
    /// </summary>
    /// <param name="fullName">The full name of the party whose log this is.</param>
    /// <param name="seq">The position in the log.</param>
    /// <param name="timeName">The creation time of the revealed key, in UTC.</param>
    /// <param name="key">The identity key this event reveals, which signs it.</param>
    /// <param name="nextCommit">
    /// The <see cref="ComputeCommit">commitment</see> to the next key, or null to abandon the identity.
    /// </param>
    /// <param name="previous">The previous event, or null for the inception.</param>
    /// <returns>The new event.</returns>
    public static KeyEvent Create( string fullName,
                                   int seq,
                                   DateTime timeName,
                                   ECDsa key,
                                   ReadOnlySpan<byte> nextCommit,
                                   KeyEvent? previous )
    {
        Throw.CheckNotNullOrEmptyArgument( fullName );
        Throw.CheckNotNullArgument( key );
        Throw.CheckArgument( timeName.Kind == DateTimeKind.Utc );
        Throw.CheckArgument( "An abandonment is written as null, never as a zero commitment.",
                             nextCommit.IsEmpty || (nextCommit.Length == HashSize && nextCommit.IndexOfAnyExcept( (byte)0 ) >= 0) );
        Throw.CheckArgument( "The inception has no previous event, every other event has one.",
                             (seq == 0) == (previous == null) );
        Throw.CheckArgument( previous == null || (seq == previous.Seq + 1 && !previous.IsAbandonment) );
        var spki = key.ExportSubjectPublicKeyInfo();
        Throw.CheckArgument( "The key must fit the bound a reader enforces.", spki.Length <= ILocalKeys.MaxPublicKeySize );
        Throw.CheckArgument( "The key must be the one the previous event committed to.",
                             previous == null || previous.CommitsTo( spki ) );
        var commit = nextCommit.IsEmpty ? new byte[HashSize] : nextCommit.ToArray();
        var prev = previous != null ? previous.GetDigest( fullName ).ToArray() : new byte[HashSize];
        var unsigned = new KeyEvent( seq, TruncateToMilliseconds( timeName ), spki, commit, prev, Array.Empty<byte>() );
        Span<byte> hash = stackalloc byte[64];
        SHA512.HashData( unsigned.GetSignedPayload( fullName ), hash );
        var signature = key.SignHash( hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
        Throw.CheckState( "Signature length must fit on one byte.", signature.Length <= 255 );
        return new KeyEvent( unsigned._seq, unsigned._timeName, spki, commit, prev, signature );
    }

    /// <summary>
    /// Verifies the signature of this event with the key it reveals.
    /// <para>
    /// This proves only that the holder of that key wrote this event. Whether the key had the right
    /// to write it is the chain's business: see <see cref="KeyEventChain"/>.
    /// </para>
    /// </summary>
    /// <param name="fullName">The full name of the party whose log this is.</param>
    /// <returns>True if the signature is valid.</returns>
    public bool VerifySignature( string fullName )
    {
        try
        {
            using var k = ECDsa.Create();
            k.ImportSubjectPublicKeyInfo( _spki, out int read );
            if( read != _spki.Length ) return false;
            Span<byte> hash = stackalloc byte[64];
            SHA512.HashData( GetSignedPayload( fullName ), hash );
            return k.VerifyHash( hash, _signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
        }
        catch( CryptographicException )
        {
            return false;
        }
    }

    /// <summary>
    /// Reads an encoded event. The signature is NOT verified here.
    /// </summary>
    /// <param name="data">The data to read from.</param>
    /// <param name="bytesRead">The number of bytes read.</param>
    /// <returns>The event.</returns>
    /// <exception cref="InvalidDataException">When the data is not an encoded event.</exception>
    public static KeyEvent Read( ReadOnlySpan<byte> data, out int bytesRead )
    {
        int p = 0;
        int seq = (int)ReadUInt32( data, ref p );
        Throw.CheckData( "Invalid event sequence number.", seq >= 0 );
        long ticks = ReadInt64( data, ref p );
        Throw.CheckData( "Invalid event time.", ticks >= DateTime.MinValue.Ticks && ticks <= DateTime.MaxValue.Ticks );
        int spkiLength = ReadUInt16( data, ref p );
        Throw.CheckData( "Invalid public key length.", spkiLength > 0 && spkiLength <= ILocalKeys.MaxPublicKeySize );
        var spki = ReadBytes( data, ref p, spkiLength );
        var next = ReadBytes( data, ref p, HashSize );
        var prev = ReadBytes( data, ref p, HashSize );
        int sigLength = ReadBytes( data, ref p, 1 )[0];
        Throw.CheckData( "Missing event signature.", sigLength > 0 );
        var sig = ReadBytes( data, ref p, sigLength );
        bool zeroPrev = prev.AsSpan().IndexOfAnyExcept( (byte)0 ) < 0;
        Throw.CheckData( "The inception, and only the inception, has no previous event.", (seq == 0) == zeroPrev );
        bytesRead = p;
        return new KeyEvent( seq, new DateTime( ticks, DateTimeKind.Utc ), spki, next, prev, sig );
    }

    /// <summary>
    /// Reads an encoded event that must span exactly <paramref name="data"/>.
    /// </summary>
    /// <param name="data">The encoded event.</param>
    /// <returns>The event.</returns>
    /// <exception cref="InvalidDataException">When the data is not exactly one encoded event.</exception>
    public static KeyEvent Read( ReadOnlySpan<byte> data )
    {
        var e = Read( data, out int read );
        Throw.CheckData( "Trailing bytes after the event.", read == data.Length );
        return e;
    }

    /// <inheritdoc />
    public override string ToString() => $"KeyEvent #{_seq} ({_timeName:u}){(IsAbandonment ? " [abandonment]" : "")}";

    byte[] GetSignedPayload( string fullName )
    {
        var name = Encoding.UTF8.GetBytes( fullName );
        var payload = new byte[DomainTag.Length + 2 + name.Length + 4 + 8 + 2 + _spki.Length + HashSize + HashSize];
        int p = 0;
        DomainTag.CopyTo( payload );
        p += DomainTag.Length;
        // Every variable-length field is length-prefixed: two different (name, key) pairs must never
        // concatenate to the same bytes.
        BinaryPrimitives.WriteUInt16LittleEndian( payload.AsSpan( p ), checked((ushort)name.Length) );
        p += 2;
        name.CopyTo( payload, p );
        p += name.Length;
        WriteFixedFields( payload.AsSpan( p ) );
        return payload;
    }

    // Seq | TimeName | spkiLength | Spki | NextCommit | PrevDigest: shared by the payload and the encoding.
    int WriteFixedFields( Span<byte> s )
    {
        int p = 0;
        BinaryPrimitives.WriteUInt32LittleEndian( s.Slice( p ), (uint)_seq );
        p += 4;
        BinaryPrimitives.WriteInt64LittleEndian( s.Slice( p ), _timeName.Ticks );
        p += 8;
        BinaryPrimitives.WriteUInt16LittleEndian( s.Slice( p ), (ushort)_spki.Length );
        p += 2;
        _spki.CopyTo( s.Slice( p ) );
        p += _spki.Length;
        _nextCommit.CopyTo( s.Slice( p ) );
        p += HashSize;
        _prevDigest.CopyTo( s.Slice( p ) );
        p += HashSize;
        return p;
    }

    byte[] Encode()
    {
        var e = new byte[4 + 8 + 2 + _spki.Length + HashSize + HashSize + 1 + _signature.Length];
        int p = WriteFixedFields( e );
        e[p++] = (byte)_signature.Length;
        _signature.CopyTo( e, p );
        return e;
    }

    static DateTime TruncateToMilliseconds( DateTime t )
        => new DateTime( t.Ticks - (t.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc );

    static ReadOnlySpan<byte> Take( ReadOnlySpan<byte> data, ref int p, int length )
    {
        Throw.CheckData( "Truncated event.", data.Length - p >= length );
        var s = data.Slice( p, length );
        p += length;
        return s;
    }

    static byte[] ReadBytes( ReadOnlySpan<byte> data, ref int p, int length ) => Take( data, ref p, length ).ToArray();
    static uint ReadUInt32( ReadOnlySpan<byte> data, ref int p ) => BinaryPrimitives.ReadUInt32LittleEndian( Take( data, ref p, 4 ) );
    static long ReadInt64( ReadOnlySpan<byte> data, ref int p ) => BinaryPrimitives.ReadInt64LittleEndian( Take( data, ref p, 8 ) );
    static ushort ReadUInt16( ReadOnlySpan<byte> data, ref int p ) => BinaryPrimitives.ReadUInt16LittleEndian( Take( data, ref p, 2 ) );
}
