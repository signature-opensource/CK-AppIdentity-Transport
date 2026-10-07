using CK.Core;
using System;
using System.Buffers.Binary;
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
/// <para>
/// <b>A crash forgets nothing.</b> The cache file is rewritten from the heartbeat; between two
/// rewrites, every nonce is first appended to a journal next to it (<c>Nonce.journal</c>), before
/// <see cref="CheckAndAdd"/> accepts it. Loading merges both, and a rewrite empties the journal. So a
/// process that crashes rejects, once restarted, exactly what a process that never stopped rejects.
/// Each append is flushed to the disk itself: neither a process crash nor an OS crash or a power loss
/// can lose it. It costs one disk sync per handshake, which is cheap at that rate.
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
    const string JournalFileName = "Nonce.journal";
    const int JournalRecordSize = 16;

    /// <summary>
    /// Test seam, deliberately not a configuration: a production switch that weakens replay
    /// protection would end up turned off "for performance". Only tests that push thousands of
    /// nonces through one remote (the memory guard) clear it, to avoid thousands of disk syncs.
    /// </summary>
    internal static bool FlushJournalToDisk = true;

    /// <summary>
    /// File format marker. Anything not starting with this is discarded rather than misread —
    /// including the previous format, a bare ulong array shared by all remotes.
    /// </summary>
    static ReadOnlySpan<byte> FileMagic => "CKNonce2"u8;

    /// <summary>
    /// Journal marker, followed by records of <see cref="JournalRecordSize"/> bytes: the nonce and its
    /// creation time. A record torn by a crash during its append is a short tail, ignored on load.
    /// </summary>
    static ReadOnlySpan<byte> JournalMagic => "CKNJrnl1"u8;

    readonly FIFOBuffer<(ulong Nonce, DateTime CreationTime)> _entries;
    readonly object _lock;
    readonly IFileStore _store;
    readonly NormalizedPath _filePath;
    readonly NormalizedPath _journalPath;
    uint _version;
    uint _savedVersion;

    RemoteNonceCache( IFileStore store, NormalizedPath filePath, FIFOBuffer<(ulong, DateTime)> entries )
    {
        _store = store;
        _filePath = filePath;
        _journalPath = filePath.RemoveLastPart().AppendPart( JournalFileName );
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
    /// <param name="journalError">
    /// Set when the nonce could not be journaled: it is accepted all the same (refusing every
    /// handshake on a full disk would be worse), but a crash before the next rewrite would forget it.
    /// </param>
    /// <returns>True if the nonce is new, false if it has already been used.</returns>
    public bool CheckAndAdd( ulong nonce, DateTime creationTime, DateTime utcNow, TimeSpan window, out bool evicted, out Exception? journalError )
    {
        lock( _lock )
        {
            journalError = null;
            DropStale( utcNow - window );
            if( Contains( nonce ) )
            {
                evicted = false;
                return false;
            }
            // Journaled before it is accepted, and under the lock: a rewrite (Save) cannot empty the
            // journal between this append and the entry it must hold.
            try
            {
                AppendToJournal( nonce, creationTime );
            }
            catch( Exception ex )
            {
                journalError = ex;
            }
            // Push drops the oldest by itself once the buffer is full: IsFull is read first only so
            // that the caller can report a peer handshaking far faster than any legitimate one.
            evicted = _entries.IsFull;
            _entries.Push( (nonce, creationTime) );
            ++_version;
            return true;
        }
    }

    bool Contains( ulong nonce )
    {
        for( int i = 0; i < _entries.Count; ++i )
        {
            if( _entries[i].Nonce == nonce ) return true;
        }
        return false;
    }

    void AppendToJournal( ulong nonce, DateTime creationTime )
    {
        // Opened per append: handshakes are rare, and holding no handle lets the rewrite and Delete
        // remove the file at any time.
        Directory.CreateDirectory( _journalPath.RemoveLastPart() );
        using var f = new FileStream( _journalPath, FileMode.Append, FileAccess.Write, FileShare.Read | FileShare.Delete );
        if( f.Position == 0 ) f.Write( JournalMagic );
        Span<byte> record = stackalloc byte[JournalRecordSize];
        BinaryPrimitives.WriteUInt64LittleEndian( record, nonce );
        BinaryPrimitives.WriteInt64LittleEndian( record.Slice( 8 ), creationTime.ToBinary() );
        f.Write( record );
        // To the disk itself, not only to the OS: a power loss must not lose it either.
        f.Flush( flushToDisk: FlushJournalToDisk );
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
            // Under the lock, files included: an append between the rewrite and the journal's
            // removal would otherwise be lost. At most MaxNonceCacheEntries entries, from the
            // heartbeat: a short hold.
            lock( _lock )
            {
                if( _savedVersion == _version ) return true;
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
                // Atomic write. A crash during a plain write leaves a truncated file that Load discards,
                // losing the entire replay record for this remote: the file on disk is always a whole
                // one - either the previous version or the new one. Missing folders are created.
                _store.WriteAllBytes( _filePath, stream.ToArray() );
                // Only then is the journal emptied: a crash in between leaves both, and Load merges them.
                if( File.Exists( _journalPath ) ) File.Delete( _journalPath );
                _savedVersion = _version;
            }
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
        // Never throws (errors are logged) and succeeds when the files don't exist.
        lock( _lock )
        {
            _store.TryTrash( monitor, _filePath, immediateDelete: true );
            _store.TryTrash( monitor, _journalPath, immediateDelete: true );
        }
    }

    /// <summary>
    /// Loads the cache of a local party's view of a remote, dropping anything that can no longer be
    /// replayed against any remote.
    /// </summary>
    public static RemoteNonceCache Load( IActivityMonitor monitor, IRemoteParty remote, ILocalParty local )
    {
        var store = remote.SharedFileStore;
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
                var bytes = store.ReadAllBytes( filePath );
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
        var cache = new RemoteNonceCache( store, filePath, entries );
        // What was accepted after the last rewrite: a crash left it there. The next rewrite folds it
        // into the file and removes the journal.
        if( cache.ReplayJournal( monitor, staleBefore ) ) cache._version = 1;
        return cache;
    }

    bool ReplayJournal( IActivityMonitor monitor, DateTime staleBefore )
    {
        if( !File.Exists( _journalPath ) ) return false;
        try
        {
            var bytes = File.ReadAllBytes( _journalPath );
            if( bytes.Length < JournalMagic.Length || !bytes.AsSpan( 0, JournalMagic.Length ).SequenceEqual( JournalMagic ) )
            {
                // Removed now: appends would otherwise follow content that is not ours.
                monitor.Info( $"Removing '{_journalPath}': not a recognized nonce journal." );
                File.Delete( _journalPath );
                return true;
            }
            int torn = (bytes.Length - JournalMagic.Length) % JournalRecordSize;
            if( torn != 0 )
            {
                // Cut now: the next appends would otherwise be misaligned, and lost to the next replay.
                using var f = new FileStream( _journalPath, FileMode.Open, FileAccess.Write, FileShare.Read | FileShare.Delete );
                f.SetLength( bytes.Length - torn );
            }
            int count = 0;
            // A torn last record (a crash during its append) is a short tail: the loop stops before it.
            for( var records = bytes.AsSpan( JournalMagic.Length ); records.Length >= JournalRecordSize; records = records.Slice( JournalRecordSize ) )
            {
                var nonce = BinaryPrimitives.ReadUInt64LittleEndian( records );
                var time = DateTime.FromBinary( BinaryPrimitives.ReadInt64LittleEndian( records.Slice( 8 ) ) );
                // Journaled entries were accepted after the file's ones: pushed after them, the
                // buffer stays (roughly) oldest first, as DropStale expects.
                if( time >= staleBefore && !Contains( nonce ) )
                {
                    _entries.Push( (nonce, time) );
                    ++count;
                }
            }
            if( count > 0 ) monitor.Info( $"Recovered {count} nonce(s) from '{_journalPath}': accepted after the last rewrite." );
            return true;
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to read '{_journalPath}'.", ex );
            return false;
        }
    }

    /// <summary>
    /// Number of nonces currently held. For tests and diagnostics.
    /// </summary>
    internal int Count
    {
        get { lock( _lock ) return _entries.Count; }
    }
}
