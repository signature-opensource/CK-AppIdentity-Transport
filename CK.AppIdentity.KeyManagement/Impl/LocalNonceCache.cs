using CK.Core;
using System;
using System.Collections.Generic;
using System.IO;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Replay cache for handshake nonces, partitioned per remote and bounded by time.
/// <para>
/// A handshake carries a nonce and a creation time. The time check bounds how long a captured
/// message stays replayable; this cache is what stops a replay <em>inside</em> that window. Without
/// it, a recorded <c>InitialMessage</c> can be resent moments later — signature still valid,
/// timestamp still in range.
/// </para>
/// <para>
/// Two properties matter, and the previous implementation had neither.
/// </para>
/// <para>
/// <b>Per remote.</b> It used to be one 1023-slot ring shared by every remote of a local party, so
/// any remote's handshakes evicted every other remote's nonces. That is not only an attack: the
/// reconnect back-off tops out at one attempt per second, so a handful of flapping remotes wrap
/// 1023 slots in about five minutes — the same order as the window the cache is meant to cover.
/// Replay protection silently degraded as remotes were added, with nothing reporting it.
/// </para>
/// <para>
/// <b>Bounded by time, not by count.</b> Any fixed-size ring can evict a nonce that is still inside
/// the replay window, which is precisely the failure. Entries are dropped when they age out of the
/// window instead, so early eviction is impossible by construction and there is no arbitrary
/// capacity to justify. <see cref="MaxEntriesPerRemote"/> remains only as a memory guard against a
/// peer handshaking absurdly fast, and hitting it degrades that one remote rather than all of them.
/// </para>
/// <para>
/// Note that nonces from a peer whose signature is only self-asserted are still recorded, on
/// purpose: forgetting them would let a message be replayed later, once that peer has been trusted.
/// Partitioning is what makes that safe — an untrusted peer can only fill its own remote's window.
/// </para>
/// </summary>
sealed class LocalNonceCache
{
    /// <summary>
    /// Memory guard per remote. See <see cref="IRemoteKeys.MaxNonceCacheEntries"/>.
    /// </summary>
    public const int MaxEntriesPerRemote = IRemoteKeys.MaxNonceCacheEntries;

    /// <summary>
    /// File format marker. A file that does not start with this is discarded rather than
    /// misinterpreted — including the previous format, which was a bare ulong array.
    /// </summary>
    static ReadOnlySpan<byte> FileMagic => "CKNonce1"u8;

    readonly Dictionary<string, Bucket> _byRemote;
    readonly object _lock;
    readonly NormalizedPath _filePath;
    uint _version;
    uint _savedVersion;

    sealed class Bucket
    {
        // Ordered oldest first: entries are appended in arrival order and pruned from the front.
        public readonly List<(ulong Nonce, DateTime CreationTime)> Entries = new();
    }

    LocalNonceCache( NormalizedPath filePath, Dictionary<string, Bucket> byRemote )
    {
        _filePath = filePath;
        _byRemote = byRemote;
        _lock = new object();
    }

    /// <summary>
    /// Atomically checks that a nonce has not been seen for this remote and records it.
    /// <para>
    /// The check and the insert are one operation on purpose: doing them separately let two
    /// concurrent connections replaying the same nonce both pass, which defeats the single-use
    /// property this cache exists to provide.
    /// </para>
    /// </summary>
    /// <param name="remoteFullName">The remote this nonce belongs to. Nonces are not shared between remotes.</param>
    /// <param name="nonce">The nonce value.</param>
    /// <param name="creationTime">The nonce's creation time, used to age it out.</param>
    /// <param name="utcNow">Current time.</param>
    /// <param name="window">The replay window: <see cref="IRemoteKeys.MaxClockOffset"/>.</param>
    /// <param name="evicted">True when the memory guard had to drop still-valid entries for this remote.</param>
    /// <returns>True if the nonce is new, false if it has already been used.</returns>
    public bool CheckAndAdd( string remoteFullName,
                             ulong nonce,
                             DateTime creationTime,
                             DateTime utcNow,
                             TimeSpan window,
                             out bool evicted )
    {
        evicted = false;
        lock( _lock )
        {
            if( !_byRemote.TryGetValue( remoteFullName, out var bucket ) )
            {
                bucket = new Bucket();
                _byRemote.Add( remoteFullName, bucket );
            }
            // A nonce is only replayable while its creation time is still within the window on
            // BOTH sides, so anything older than that cannot be replayed and need not be kept.
            var oldest = utcNow - window;
            var entries = bucket.Entries;
            int drop = 0;
            while( drop < entries.Count && entries[drop].CreationTime < oldest ) ++drop;
            if( drop > 0 ) entries.RemoveRange( 0, drop );

            for( int i = 0; i < entries.Count; ++i )
            {
                if( entries[i].Nonce == nonce ) return false;
            }
            if( entries.Count >= MaxEntriesPerRemote )
            {
                // Only reachable by a peer handshaking far faster than any legitimate one. Drop the
                // oldest still-valid entry: the degradation is confined to this remote.
                entries.RemoveAt( 0 );
                evicted = true;
            }
            entries.Add( (nonce, creationTime) );
            ++_version;
            return true;
        }
    }

    /// <summary>
    /// Drops every entry that has aged out, and any remote left with none.
    /// Called from the heartbeat so an idle process does not hold nonces indefinitely.
    /// </summary>
    public void Prune( DateTime utcNow, TimeSpan window )
    {
        lock( _lock )
        {
            var oldest = utcNow - window;
            List<string>? empty = null;
            foreach( var (name, bucket) in _byRemote )
            {
                var entries = bucket.Entries;
                int drop = 0;
                while( drop < entries.Count && entries[drop].CreationTime < oldest ) ++drop;
                if( drop > 0 )
                {
                    entries.RemoveRange( 0, drop );
                    ++_version;
                }
                if( entries.Count == 0 ) (empty ??= new List<string>()).Add( name );
            }
            if( empty != null )
            {
                foreach( var name in empty ) _byRemote.Remove( name );
            }
        }
    }

    /// <summary>
    /// Called from the ApplicationIdentity's loop by the heartbeat or by the local keys OnTearDown.
    /// This saves only if something changed since the last save.
    /// </summary>
    /// <param name="monitor">The ApplicationIdentity's agent monitor.</param>
    /// <returns>True on success, false if an error occured.</returns>
    public bool Save( IActivityMonitor monitor )
    {
        try
        {
            using var stream = new MemoryStream();
            using( var w = new BinaryWriter( stream, System.Text.Encoding.UTF8, leaveOpen: true ) )
            {
                lock( _lock )
                {
                    if( _savedVersion == _version ) return true;
                    _savedVersion = _version;
                    w.Write( FileMagic );
                    w.Write( _byRemote.Count );
                    foreach( var (name, bucket) in _byRemote )
                    {
                        w.Write( name );
                        w.Write( bucket.Entries.Count );
                        foreach( var (nonce, time) in bucket.Entries )
                        {
                            w.Write( nonce );
                            w.Write( time.ToBinary() );
                        }
                    }
                }
            }
            File.WriteAllBytes( _filePath, stream.ToArray() );
            return true;
        }
        catch( Exception ex )
        {
            monitor.Error( $"While saving '{_filePath}'.", ex );
            return false;
        }
    }

    internal static LocalNonceCache Create( IActivityMonitor monitor, NormalizedPath filePath )
    {
        var byRemote = new Dictionary<string, Bucket>();
        var staleBefore = DateTime.UtcNow - IRemoteKeys.MaxAllowedClockOffset;
        try
        {
            if( File.Exists( filePath ) )
            {
                var bytes = File.ReadAllBytes( filePath );
                if( bytes.Length >= FileMagic.Length && bytes.AsSpan( 0, FileMagic.Length ).SequenceEqual( FileMagic ) )
                {
                    using var r = new BinaryReader( new MemoryStream( bytes, FileMagic.Length, bytes.Length - FileMagic.Length ) );
                    int remoteCount = r.ReadInt32();
                    for( int i = 0; i < remoteCount; ++i )
                    {
                        var name = r.ReadString();
                        int count = r.ReadInt32();
                        // Bounded by what we would ourselves have written: a corrupt or hostile file
                        // must not make us allocate.
                        Throw.CheckData( count >= 0 && count <= MaxEntriesPerRemote );
                        var bucket = new Bucket();
                        for( int j = 0; j < count; ++j )
                        {
                            var nonce = r.ReadUInt64();
                            var time = DateTime.FromBinary( r.ReadInt64() );
                            // Drop what can no longer be replayed against ANY remote. No remote can
                            // be configured above MaxAllowedClockOffset, so an older nonce would be
                            // refused on its timestamp before the cache was ever consulted. Keeping
                            // it would only grow the file across restarts.
                            if( time >= staleBefore ) bucket.Entries.Add( (nonce, time) );
                        }
                        if( bucket.Entries.Count > 0 ) byRemote.Add( name, bucket );
                    }
                }
                else
                {
                    // Includes the previous format (a bare ulong array with the head in its last
                    // slot). Starting empty is safe: it only forgets nonces, and anything still
                    // replayable is bounded by the clock window.
                    monitor.Info( $"Ignoring '{filePath}': not a recognized nonce cache. Starting empty." );
                }
            }
            else
            {
                monitor.Trace( $"Creating '{filePath}' file." );
            }
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to read '{filePath}'. Starting with an empty nonce cache.", ex );
            byRemote.Clear();
        }
        return new LocalNonceCache( filePath, byRemote );
    }

    /// <summary>
    /// Number of remotes currently holding at least one nonce. For tests and diagnostics.
    /// </summary>
    internal int RemoteCount
    {
        get
        {
            lock( _lock ) return _byRemote.Count;
        }
    }

    /// <summary>
    /// Number of nonces held for a remote. For tests and diagnostics.
    /// </summary>
    internal int CountFor( string remoteFullName )
    {
        lock( _lock ) return _byRemote.TryGetValue( remoteFullName, out var b ) ? b.Entries.Count : 0;
    }
}
