using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The state of the approval code (a short authentication string) between a local party and one remote, kept by the
/// remote's <see cref="TransportFeature"/> across the connection attempts.
/// <para>
/// The code binds both full names, both identity keys and a nonce of each side: the initiator commits to its nonce
/// (<c>H(nI)</c> in its initial message) before the listener answers its own (<c>nL</c> in its rejection), then reveals
/// it (in its RequiredEnlistUrl reply). Neither side can choose its values once it knows the other's, so an attacker
/// can't search for a key whose code matches the one an operator reads: each pending item is one chance in 10^8.
/// </para>
/// <para>
/// The rules that keep it so across the retries: each side's own nonce is fresh per item, the peer's value (its
/// commitment, or its nonce) is fixed at its first reception, and a different value starts a new item. The initiator
/// reveals its nonce to one listener key only.
/// </para>
/// </summary>
sealed class ApprovalSession
{
    /// <summary>
    /// The length of a nonce and of a commitment.
    /// </summary>
    public const int NonceLength = 32;

    /// <summary>
    /// The maximal number of keys a listener keeps per remote: above, the oldest item is forgotten.
    /// </summary>
    public const int MaxPendingKeys = 4;

    /// <summary>
    /// The lifetime of a listener's item.
    /// </summary>
    public static readonly TimeSpan PendingLifetime = TimeSpan.FromHours( 1 );

    static ReadOnlySpan<byte> _label => "CK-AppIdentity-SAS"u8;

    readonly object _lock;

    // Initiator side: our nonce, its commitment, the listener key it has been revealed to and the listener's
    // nonce received first for this key.
    byte[]? _ownNonce;
    byte[]? _ownCommitment;
    KeyEvent? _boundHead;
    byte[]? _peerNonce;
    string? _lastLoggedInitiatorCode;

    // Listener side: an item per initiator key.
    readonly List<Pending> _pending;

    sealed class Pending
    {
        public required KeyEvent Head { get; init; }
        public required string Fingerprint { get; init; }
        public required byte[] Commitment { get; set; }
        public required byte[] Nonce { get; set; }
        public byte[]? PeerNonce { get; set; }
        public required DateTime Expires { get; set; }
        public string? LastLoggedCode { get; set; }
    }

    public ApprovalSession()
    {
        _lock = new object();
        _pending = new List<Pending>();
    }

    #region Initiator side.

    /// <summary>
    /// Gets the commitment to our nonce, for the initial message.
    /// </summary>
    public byte[] GetCommitment()
    {
        lock( _lock )
        {
            if( _ownCommitment == null ) NewOwnNonce();
            return _ownCommitment!;
        }
    }

    void NewOwnNonce()
    {
        _ownNonce = RandomNumberGenerator.GetBytes( NonceLength );
        _ownCommitment = SHA256.HashData( _ownNonce );
        _boundHead = null;
        _peerNonce = null;
    }

    /// <summary>
    /// Handles the listener's nonce of a rejection and returns our nonce to reveal, or null when it must not be
    /// revealed: the listener answers with another key or another nonce than the ones our nonce is bound to (a new
    /// nonce is drawn, committed at the next attempt), or our nonce changed since <paramref name="sentCommitment"/>.
    /// </summary>
    /// <param name="listenerHead">The head of the listener's key event log, in its signed rejection.</param>
    /// <param name="listenerNonce">The listener's nonce (null when it sent none).</param>
    /// <param name="sentCommitment">The commitment sent by this connection's initial message.</param>
    /// <returns>Our nonce to reveal, or null.</returns>
    public byte[]? OnReply( KeyEvent listenerHead, byte[]? listenerNonce, byte[] sentCommitment )
    {
        lock( _lock )
        {
            if( listenerNonce == null || _ownCommitment == null || !_ownCommitment.AsSpan().SequenceEqual( sentCommitment ) )
            {
                return null;
            }
            if( _boundHead == null )
            {
                _boundHead = listenerHead;
                _peerNonce = listenerNonce;
                return _ownNonce;
            }
            if( SameKey( _boundHead, listenerHead ) && _peerNonce.AsSpan().SequenceEqual( listenerNonce ) )
            {
                return _ownNonce;
            }
            // Another key, or another nonce for the same key: our nonce has been revealed, it can't be reused.
            NewOwnNonce();
            return null;
        }
    }

    /// <summary>
    /// Gets the code, once our nonce has been revealed to a listener key: <paramref name="listenerHead"/> when it is
    /// not null (null when it is another key), any key otherwise.
    /// </summary>
    public string? GetInitiatorCode( string initiatorFullName, KeyEvent initiatorHead, string listenerFullName, KeyEvent? listenerHead )
    {
        lock( _lock )
        {
            if( _boundHead == null || (listenerHead != null && !SameKey( _boundHead, listenerHead )) ) return null;
            return Compute( initiatorFullName, initiatorHead, listenerFullName, _boundHead, _ownNonce!, _peerNonce! );
        }
    }

    /// <summary>
    /// Returns the code when it has not been logged yet (initiator side).
    /// </summary>
    public string? GetInitiatorCodeToLog( string initiatorFullName, KeyEvent initiatorHead, string listenerFullName, KeyEvent listenerHead )
    {
        lock( _lock )
        {
            var code = GetInitiatorCode( initiatorFullName, initiatorHead, listenerFullName, listenerHead );
            if( code == null || code == _lastLoggedInitiatorCode ) return null;
            _lastLoggedInitiatorCode = code;
            return code;
        }
    }

    #endregion

    #region Listener side.

    /// <summary>
    /// Handles the commitment of an initial message and returns our nonce for the initiator's key.
    /// </summary>
    /// <param name="initiatorHead">The head of the initiator's key event log.</param>
    /// <param name="commitment">The commitment of the initial message.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>Our nonce for this key.</returns>
    public byte[] OnInitial( KeyEvent initiatorHead, byte[] commitment, DateTime utcNow )
    {
        lock( _lock )
        {
            _pending.RemoveAll( p => p.Expires <= utcNow );
            var fingerprint = Fingerprint( initiatorHead );
            var item = _pending.Find( p => p.Fingerprint == fingerprint );
            if( item == null )
            {
                if( _pending.Count >= MaxPendingKeys ) _pending.RemoveAt( 0 );
                item = new Pending
                {
                    Head = initiatorHead,
                    Fingerprint = fingerprint,
                    Commitment = commitment,
                    Nonce = RandomNumberGenerator.GetBytes( NonceLength ),
                    Expires = utcNow + PendingLifetime
                };
                _pending.Add( item );
            }
            else if( !item.Commitment.AsSpan().SequenceEqual( commitment ) )
            {
                // Only the holder of this key can sign another commitment for it (it restarted, or it drew a new
                // nonce): a new item, with a new nonce of ours.
                item.Commitment = commitment;
                item.Nonce = RandomNumberGenerator.GetBytes( NonceLength );
                item.PeerNonce = null;
                item.Expires = utcNow + PendingLifetime;
            }
            return item.Nonce;
        }
    }

    /// <summary>
    /// Handles the initiator's revealed nonce: kept when it matches the commitment of its key's item.
    /// </summary>
    /// <returns>True when the nonce matches the commitment.</returns>
    public bool OnReveal( KeyEvent initiatorHead, byte[] initiatorNonce )
    {
        lock( _lock )
        {
            var item = _pending.Find( p => p.Fingerprint == Fingerprint( initiatorHead ) );
            if( item == null || !item.Commitment.AsSpan().SequenceEqual( SHA256.HashData( initiatorNonce ) ) ) return false;
            item.PeerNonce = initiatorNonce;
            return true;
        }
    }

    /// <summary>
    /// Gets the code of the item of <paramref name="initiatorHead"/> (listener side), once its nonce has been revealed.
    /// </summary>
    public string? GetListenerCode( string initiatorFullName, KeyEvent initiatorHead, string listenerFullName, KeyEvent listenerHead )
    {
        lock( _lock )
        {
            var item = _pending.Find( p => p.Fingerprint == Fingerprint( initiatorHead ) );
            return item?.PeerNonce != null
                    ? Compute( initiatorFullName, item.Head, listenerFullName, listenerHead, item.PeerNonce, item.Nonce )
                    : null;
        }
    }

    /// <summary>
    /// Returns the code of the item of <paramref name="initiatorHead"/> when it has not been logged yet (listener side).
    /// </summary>
    public string? GetListenerCodeToLog( string initiatorFullName, KeyEvent initiatorHead, string listenerFullName, KeyEvent listenerHead )
    {
        lock( _lock )
        {
            var item = _pending.Find( p => p.Fingerprint == Fingerprint( initiatorHead ) );
            if( item?.PeerNonce == null ) return null;
            var code = Compute( initiatorFullName, item.Head, listenerFullName, listenerHead, item.PeerNonce, item.Nonce );
            if( code == item.LastLoggedCode ) return null;
            item.LastLoggedCode = code;
            return code;
        }
    }

    /// <summary>
    /// Finds the item whose code is <paramref name="code"/> (listener side) and returns its initiator's key.
    /// </summary>
    /// <param name="code">The normalized code (8 digits, see <see cref="TryNormalize"/>).</param>
    /// <param name="hasPendingReveal">True when no item matches but an item still waits for its reveal.</param>
    /// <returns>The key to pin, or null.</returns>
    public KeyEvent? FindListenerApproval( string code, string initiatorFullName, string listenerFullName, KeyEvent listenerHead, DateTime utcNow, out bool hasPendingReveal )
    {
        lock( _lock )
        {
            _pending.RemoveAll( p => p.Expires <= utcNow );
            hasPendingReveal = false;
            foreach( var p in _pending )
            {
                if( p.PeerNonce == null )
                {
                    hasPendingReveal = true;
                    continue;
                }
                if( Compute( initiatorFullName, p.Head, listenerFullName, listenerHead, p.PeerNonce, p.Nonce ) == code )
                {
                    hasPendingReveal = false;
                    return p.Head;
                }
            }
            return null;
        }
    }

    #endregion

    /// <summary>
    /// Forgets everything: the remote is connected.
    /// </summary>
    public void Clear()
    {
        lock( _lock )
        {
            _ownNonce = null;
            _ownCommitment = null;
            _boundHead = null;
            _peerNonce = null;
            _lastLoggedInitiatorCode = null;
            _pending.Clear();
        }
    }

    static string Fingerprint( KeyEvent head ) => PublicKeyFingerprint.Compute( head.Spki.Span );

    static bool SameKey( KeyEvent a, KeyEvent b ) => a.Spki.Span.SequenceEqual( b.Spki.Span );

    /// <summary>
    /// Normalizes a code entered by an operator: its 8 digits, the separators (spaces, dashes) are ignored.
    /// </summary>
    /// <param name="code">The entered code.</param>
    /// <param name="normalized">The code as <see cref="Compute"/> formats it.</param>
    /// <returns>True when the code has exactly 8 digits.</returns>
    public static bool TryNormalize( string? code, out string normalized )
    {
        normalized = string.Empty;
        if( code == null ) return false;
        var digits = new StringBuilder( 8 );
        foreach( var c in code )
        {
            if( c is >= '0' and <= '9' ) digits.Append( c );
            else if( c is not (' ' or '-') ) return false;
        }
        if( digits.Length != 8 ) return false;
        normalized = string.Concat( digits.ToString( 0, 4 ), "-", digits.ToString( 4, 4 ) );
        return true;
    }

    /// <summary>
    /// Computes the code: 8 decimal digits ("1234-5678") of the SHA-256 of a label, both full names, the SHA-256 of
    /// both identity keys (their SubjectPublicKeyInfo) and both nonces.
    /// </summary>
    internal static string Compute( string initiatorFullName,
                                    KeyEvent initiatorHead,
                                    string listenerFullName,
                                    KeyEvent listenerHead,
                                    byte[] initiatorNonce,
                                    byte[] listenerNonce )
    {
        using var h = IncrementalHash.CreateHash( HashAlgorithmName.SHA256 );
        h.AppendData( _label );
        AppendName( h, initiatorFullName );
        AppendName( h, listenerFullName );
        h.AppendData( SHA256.HashData( initiatorHead.Spki.Span ) );
        h.AppendData( SHA256.HashData( listenerHead.Spki.Span ) );
        h.AppendData( initiatorNonce );
        h.AppendData( listenerNonce );
        Span<byte> hash = stackalloc byte[32];
        h.GetCurrentHash( hash );
        var v = BinaryPrimitives.ReadUInt64BigEndian( hash ) % 100_000_000UL;
        return $"{v / 10_000:D4}-{v % 10_000:D4}";

        static void AppendName( IncrementalHash h, string name )
        {
            // A full name never contains a 0: it separates the names.
            h.AppendData( Encoding.UTF8.GetBytes( name ) );
            h.AppendData( [0] );
        }
    }
}
