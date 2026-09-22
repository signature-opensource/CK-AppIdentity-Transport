using CK.Core;
using System;
using System.IO;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Replay cache of handshake nonces seen from ONE remote, bounded by time.
/// <para>
/// A handshake carries a nonce and a creation time. The time check bounds how long a captured
/// message stays replayable; this cache is what stops a replay <em>inside</em> that window. Without
/// it a recorded <c>InitialMessage</c> can be resent moments later — signature still valid,
/// timestamp still in range.
/// </para>
/// <para>
/// <b>One cache per remote.</b> A single ring shared by every remote of a local party is a weaker
/// design than it looks: any remote's handshakes then evict every other remote's nonces. That is
/// not only an attack. The reconnect back-off tops out at one attempt per second, so a handful of
/// flapping remotes wrap a thousand slots in about five minutes — the same order as the window the
/// cache exists to cover. Replay protection would degrade as remotes are added, silently.
/// </para>
/// <para>
/// <b>Bounded by time, then by count.</b> Any fixed-size ring can evict a nonce that is still inside
/// the replay window, which is exactly the failure. Entries are normally dropped once they age out,
/// so in steady state eviction is driven by time alone. The capacity
/// (<see cref="IRemoteKeys.MaxNonceCacheEntries"/>) is a memory guard against a peer handshaking
/// absurdly fast, and it degrades that peer alone - but it IS a real bound: <c>CheckAndAdd</c>
/// reports <c>evicted</c> when it bites, so "impossible by construction" would overstate it.
/// </para>
/// <para>
/// Nonces from a peer whose signature is merely self-asserted are recorded too, on purpose:
/// forgetting them would let a message be replayed later, once that peer has been trusted. Holding
/// the cache per remote is what makes that safe.
/// </para>
/// </summary>
sealed class RemoteNonceCache
{
    /// <summary>
    /// Sub-folder of a remote's shared store holding the per-local-party caches.
    /// <para>
    /// The remote's folder is shared by every local party on this file system, which is the point:
    /// a remote's data belongs to the remote. This cache is not data about the remote though — it
    /// is one local party's record of what it has seen — so each local party gets its own file
    /// under here, named by its full name.
    /// </para>
    /// <para>
    /// The separation is for writers, not for secrecy: sharing one file would be marginally safer
    /// (a message replayed from one local party to another would be caught), but those folders are
    /// shared across OS processes, and several processes writing one file corrupt it or fail. A
    /// cross-local replay is a dead end anyway — the attacker can sign neither the FinalSuccess nor
    /// anything in the run phase.
    /// </para>
    /// </summary>
    public const string LocalsFolderName = "-Locals";

    const string FileName = "Nonce.cache";

    /// <summary>
    /// File format marker. Anything not starting with this is discarded rather than misread —
    /// including the previous format, a bare ulong array shared by all remotes.
    /// </summary>
    static ReadOnlySpan<byte> FileMagic => "CKNonce2"u8;

    readonly FIFOBuffer<(ulong Nonce, DateTime CreationTime)> _entries;
    readonly object _lock;
    readonly NormalizedPath _filePath;
    uint _version;
    uint _savedVersion;

    RemoteNonceCache( NormalizedPath filePath, FIFOBuffer<(ulong, DateTime)> entries )
    {
        _filePath = filePath;
        _entries = entries;
        _lock = new object();
    }

    /// <summary>
    /// Gets the cache file for a local party's view of a remote.
    /// </summary>
    public static NormalizedPath GetFilePath( IRemoteParty remote, ILocalParty local )
        => remote.SharedFileStore.FolderPath
                 .AppendPart( LocalsFolderName )
                 .Combine( local.FullName )
                 .AppendPart( FileName );

    /// <summary>
    /// Atomically checks that a nonce has not been seen from this remote and records it.
    /// <para>
    /// Check and insert are one operation on purpose: done separately, two concurrent connections
    /// replaying the same nonce could both pass, which defeats the single-use property this cache
    /// exists to provide.
    /// </para>
    /// </summary>
    /// <param name="nonce">The nonce value.</param>
    /// <param name="creationTime">Its creation time, used to age it out.</param>
    /// <param name="utcNow">Current time.</param>
    /// <param name="window">The replay window: <see cref="IRemoteKeys.MaxClockOffset"/>.</param>
    /// <param name="evicted">True when the memory guard had to drop a still-valid entry.</param>
    /// <returns>True if the nonce is new, false if it has already been used.</returns>
    public bool CheckAndAdd( ulong nonce, DateTime creationTime, DateTime utcNow, TimeSpan window, out bool evicted )
    {
        lock( _lock )
        {
            DropStale( utcNow - window );
            for( int i = 0; i < _entries.Count; ++i )
            {
                if( _entries[i].Nonce == nonce )
                {
                    evicted = false;
                    return false;
                }
            }
            // Push drops the oldest by itself once the buffer is full: IsFull is read first only so
            // that the caller can report a peer handshaking far faster than any legitimate one.
            evicted = _entries.IsFull;
            _entries.Push( (nonce, creationTime) );
            ++_version;
            return true;
        }
    }

    /// <summary>
    /// Drops entries that have aged out. Called from the heartbeat so an idle process does not hold
    /// nonces that can no longer be replayed.
    /// </summary>
    public void Prune( DateTime utcNow, TimeSpan window )
    {
        lock( _lock ) DropStale( utcNow - window );
    }

    // Entries are ordered oldest first, so ageing out is a prefix: Pop is O(1) on the circular
    // buffer, where a List would have to shift everything that survives on every call.
    void DropStale( DateTime oldest )
    {
        while( _entries.Count > 0 && _entries[0].CreationTime < oldest )
        {
            _entries.Pop();
            ++_version;
        }
    }

    /// <summary>
    /// Persists the cache, only if something changed since the last save.
    /// </summary>
    public bool Save( IActivityMonitor monitor )
    {
        try
        {
            byte[] bytes;
            lock( _lock )
            {
                if( _savedVersion == _version ) return true;
                _savedVersion = _version;
                using var stream = new MemoryStream();
                using( var w = new BinaryWriter( stream ) )
                {
                    w.Write( FileMagic );
                    w.Write( _entries.Count );
                    for( int i = 0; i < _entries.Count; ++i )
                    {
                        w.Write( _entries[i].Nonce );
                        w.Write( _entries[i].CreationTime.ToBinary() );
                    }
                }
                bytes = stream.ToArray();
            }
            Directory.CreateDirectory( _filePath.RemoveLastPart() );
            // Temp-plus-rename. A crash during a plain write leaves a truncated file that Load
            // discards, losing the entire replay record for this remote; the rename is atomic, so the
            // file on disk is always a whole one - either the previous version or the new one.
            var tmp = _filePath + ".new";
            File.WriteAllBytes( tmp, bytes );
            File.Move( tmp, _filePath, overwrite: true );
            return true;
        }
        catch( Exception ex )
        {
            monitor.Error( $"While saving '{_filePath}'.", ex );
            return false;
        }
    }

    /// <summary>
    /// Removes the persisted cache. Called when the remote is destroyed: its replay record has no
    /// meaning any more, and leaving it behind would resurrect on a party of the same name.
    /// </summary>
    public void Delete( IActivityMonitor monitor )
    {
        try
        {
            if( File.Exists( _filePath ) ) File.Delete( _filePath );
        }
        catch( Exception ex )
        {
            monitor.Warn( $"While deleting '{_filePath}'.", ex );
        }
    }

    /// <summary>
    /// Loads the cache of a local party's view of a remote, dropping anything that can no longer be
    /// replayed against any remote.
    /// </summary>
    public static RemoteNonceCache Load( IActivityMonitor monitor, IRemoteParty remote, ILocalParty local )
    {
        var filePath = GetFilePath( remote, local );
        // No remote can be configured above MaxAllowedClockOffset, so an older nonce would be
        // refused on its timestamp before this cache was ever consulted: loading it back would only
        // grow the file across restarts.
        var staleBefore = remote.ApplicationIdentityService.SystemClock.UtcNow - IRemoteKeys.MaxAllowedClockOffset;
        var entries = new FIFOBuffer<(ulong, DateTime)>( 0, IRemoteKeys.MaxNonceCacheEntries );
        try
        {
            if( File.Exists( filePath ) )
            {
                var bytes = File.ReadAllBytes( filePath );
                if( bytes.Length >= FileMagic.Length && bytes.AsSpan( 0, FileMagic.Length ).SequenceEqual( FileMagic ) )
                {
                    using var r = new BinaryReader( new MemoryStream( bytes, FileMagic.Length, bytes.Length - FileMagic.Length ) );
                    int count = r.ReadInt32();
                    // A corrupt or hostile file must not make us allocate: the buffer caps itself,
                    // but the loop must not be driven by an arbitrary number either.
                    Throw.CheckData( count >= 0 && count <= IRemoteKeys.MaxNonceCacheEntries );
                    for( int i = 0; i < count; ++i )
                    {
                        var nonce = r.ReadUInt64();
                        var time = DateTime.FromBinary( r.ReadInt64() );
                        if( time >= staleBefore ) entries.Push( (nonce, time) );
                    }
                }
                else
                {
                    monitor.Info( $"Ignoring '{filePath}': not a recognized nonce cache. Starting empty." );
                }
            }
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to read '{filePath}'. Starting with an empty nonce cache.", ex );
            entries.Clear();
        }
        return new RemoteNonceCache( filePath, entries );
    }

    /// <summary>
    /// Number of nonces currently held. For tests and diagnostics.
    /// </summary>
    internal int Count
    {
        get { lock( _lock ) return _entries.Count; }
    }
}
