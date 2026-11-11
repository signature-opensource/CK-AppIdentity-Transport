using CK.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The nonces of the seals of the routed commands that have been used (see <see cref="RoutedCommandSeal"/>), until the end
/// of their lifetime: a seal is used once.
/// <para>
/// A restart forgets nothing (like the handshake nonces of CK.AppIdentity.KeyManagement): every nonce is appended to a
/// journal in the local store, flushed to the disk, before it is accepted; the journal is read at start and rewritten
/// without the expired nonces by <see cref="Compact"/>. A nonce that can't be journaled is refused (fail closed).
/// </para>
/// <para>
/// The nonces expire in the order they are used (up to the clock skew between the session parties): they are dropped from
/// the front of a queue, never by scanning all of them.
/// </para>
/// </summary>
sealed class AuthCenterSealNonces
{
    // The journal: this marker, then records of the expiration ticks (8 bytes), the length of the nonce (1 byte) and its
    // ASCII bytes. A record torn by a crash is a short tail, ignored on load.
    static ReadOnlySpan<byte> Magic => "CKSealN1"u8;

    readonly Dictionary<string, DateTime> _nonces;
    readonly Queue<(string Nonce, DateTime Expires)> _order;
    readonly IFileStore _store;
    readonly NormalizedPath _path;
    readonly object _lock;

    internal AuthCenterSealNonces( IActivityMonitor monitor, IFileStore store, NormalizedPath path, DateTime utcNow )
    {
        _store = store;
        _path = path;
        _lock = new object();
        _nonces = new Dictionary<string, DateTime>( StringComparer.Ordinal );
        _order = new Queue<(string, DateTime)>();
        Load( monitor, utcNow );
    }

    /// <summary>
    /// Gets the number of nonces held.
    /// </summary>
    internal int Count
    {
        get
        {
            lock( _lock ) return _nonces.Count;
        }
    }

    /// <summary>
    /// Uses a nonce: false when it has already been used, or when it can't be journaled (the reason is logged).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="nonce">The nonce of the seal.</param>
    /// <param name="expires">The end of the lifetime of the seal.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>True when the nonce is used for the first time.</returns>
    internal bool TryUse( IActivityMonitor monitor, string nonce, DateTime expires, DateTime utcNow )
    {
        Throw.CheckArgument( nonce.Length is > 0 and <= 255 );
        lock( _lock )
        {
            DropExpired( utcNow );
            if( _nonces.ContainsKey( nonce ) ) return false;
            try
            {
                Append( nonce, expires );
            }
            catch( Exception ex ) when( ex is IOException or UnauthorizedAccessException )
            {
                monitor.Error( $"The nonce of a seal can't be written to '{_path}': the seal is refused.", ex );
                return false;
            }
            _nonces.Add( nonce, expires );
            _order.Enqueue( (nonce, expires) );
            return true;
        }
    }

    /// <summary>
    /// Drops the expired nonces and rewrites the journal with the other ones.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="utcNow">The current time.</param>
    internal void Compact( IActivityMonitor monitor, DateTime utcNow )
    {
        lock( _lock )
        {
            // A full pass (hourly): the expired nonces left behind a later one (the clock skew) are dropped too.
            var kept = new List<(string Nonce, DateTime Expires)>( _order.Count );
            foreach( var e in _order )
            {
                if( e.Expires > utcNow ) kept.Add( e );
                else _nonces.Remove( e.Nonce );
            }
            _order.Clear();
            foreach( var e in kept ) _order.Enqueue( e );
            Directory.CreateDirectory( _path.RemoveLastPart() );
            _store.WriteAtomically( _path, s =>
            {
                s.Write( Magic );
                foreach( var (nonce, expires) in kept ) WriteRecord( s, nonce, expires );
            } );
        }
    }

    void DropExpired( DateTime utcNow )
    {
        while( _order.TryPeek( out var first ) && first.Expires <= utcNow )
        {
            _order.Dequeue();
            _nonces.Remove( first.Nonce );
        }
    }

    void Append( string nonce, DateTime expires )
    {
        Directory.CreateDirectory( _path.RemoveLastPart() );
        using var f = new FileStream( _path, FileMode.Append, FileAccess.Write, FileShare.Read | FileShare.Delete );
        if( f.Position == 0 ) f.Write( Magic );
        WriteRecord( f, nonce, expires );
        // To the disk itself: a crash or a power loss must not lose it.
        f.Flush( flushToDisk: true );
    }

    static void WriteRecord( Stream s, string nonce, DateTime expires )
    {
        Span<byte> record = stackalloc byte[8 + 1 + 255];
        BinaryPrimitives.WriteInt64LittleEndian( record, expires.Ticks );
        int length = Encoding.ASCII.GetBytes( nonce, record.Slice( 9 ) );
        record[8] = (byte)length;
        s.Write( record.Slice( 0, 9 + length ) );
    }

    void Load( IActivityMonitor monitor, DateTime utcNow )
    {
        var bytes = _store.TryReadAllBytes( _path );
        if( bytes == null ) return;
        ReadOnlySpan<byte> s = bytes;
        if( !s.StartsWith( Magic ) )
        {
            monitor.Warn( $"'{_path}' is not a journal of seal nonces: it is ignored." );
            return;
        }
        s = s.Slice( Magic.Length );
        while( s.Length >= 9 )
        {
            long ticks = BinaryPrimitives.ReadInt64LittleEndian( s );
            int length = s[8];
            if( s.Length < 9 + length ) break;
            if( ticks >= DateTime.MinValue.Ticks && ticks <= DateTime.MaxValue.Ticks && length > 0 )
            {
                var expires = new DateTime( ticks, DateTimeKind.Utc );
                var nonce = Encoding.ASCII.GetString( s.Slice( 9, length ) );
                if( expires > utcNow && _nonces.TryAdd( nonce, expires ) ) _order.Enqueue( (nonce, expires) );
            }
            s = s.Slice( 9 + length );
        }
    }
}
