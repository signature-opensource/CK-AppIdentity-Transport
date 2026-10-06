using CK.AppIdentity.KeyManagement;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Testing.Adversarial;

/// <summary>
/// The identity the adversarial peer presents: a key event log of its own, the current key that
/// signs, and the committed next key.
/// <para>
/// Unlike the production <c>LocalKeys</c> this is not backed by a key store or a certificate: the
/// Zero Protocol transmits events and one signature, so key pairs are everything a peer needs.
/// What a peer cannot do with key pairs alone is move a pin it does not own: the next event must
/// reveal the key the previous one committed to. Whether a test can get past that is the subject of
/// <c>KeyTakeoverTests</c>.
/// </para>
/// <para>
/// Events are signed for <see cref="FullName"/>: it must be the name the other side knows this peer
/// by, e.g. "Test/$AdvPeer/#Dev".
/// </para>
/// </summary>
public sealed class PeerIdentity : IDisposable
{
    // Key i is revealed by event i; the last key is the committed next one. Null where the key is
    // unknown (an adopted log only holds the keys that were stolen).
    readonly List<ECDsa?> _keys;
    readonly List<KeyEvent> _events;
    readonly bool _ownsKeys;
    // Issued lazily for the current key, and dropped when the head changes.
    PeerCredential? _credential;

    PeerIdentity( string fullName, bool ownsKeys = true )
    {
        FullName = fullName;
        _keys = new List<ECDsa?>();
        _events = new List<KeyEvent>();
        _ownsKeys = ownsKeys;
    }

    /// <summary>
    /// A peer presenting someone else's log with keys it obtained: what a thief does. The keys stay
    /// owned by the caller.
    /// </summary>
    /// <param name="fullName">The name of the party whose log this is.</param>
    /// <param name="events">The events presented, from the inception.</param>
    /// <param name="currentKey">The key the last event reveals: it signs.</param>
    /// <param name="nextKey">The key the last event commits to, if known.</param>
    public static PeerIdentity Adopt( string fullName, IEnumerable<KeyEvent> events, ECDsa currentKey, ECDsa? nextKey = null )
    {
        var id = new PeerIdentity( fullName, ownsKeys: false );
        id._events.AddRange( events );
        for( int i = 0; i < id.Head.Seq; ++i ) id._keys.Add( null );
        id._keys.Add( currentKey );
        id._keys.Add( nextKey );
        return id;
    }

    /// <summary>
    /// Creates a fresh identity: an inception that commits to a next key.
    /// </summary>
    /// <param name="fullName">The name the other side knows this peer by, e.g. "Test/$AdvPeer/#Dev".</param>
    /// <param name="timeName">The inception's time. Defaults to "a moment ago".</param>
    public static PeerIdentity Create( string fullName, DateTime? timeName = null )
    {
        var id = new PeerIdentity( fullName );
        id._keys.Add( NewKey() );
        id._keys.Add( NewKey() );
        var t = timeName ?? DateTime.UtcNow.AddMinutes( -1 );
        if( t.Kind != DateTimeKind.Utc ) throw new ArgumentException( "TimeName must be UTC.", nameof( timeName ) );
        id._events.Add( KeyEvent.Create( fullName, 0, t, id._keys[0]!, Commit( id._keys[1]! ), null ) );
        return id;
    }

    /// <summary>The name events are signed for.</summary>
    public string FullName { get; }

    /// <summary>The whole log, from the inception.</summary>
    public IReadOnlyList<KeyEvent> Events => _events;

    /// <summary>The last events (at most <see cref="KeyEventChain.MaxEventTail"/>): what is presented.</summary>
    public IReadOnlyList<KeyEvent> Tail => _events.Count <= KeyEventChain.MaxEventTail
                                            ? _events
                                            : _events.Skip( _events.Count - KeyEventChain.MaxEventTail ).ToList();

    /// <summary>The head of the log.</summary>
    public KeyEvent Head => _events[^1];

    /// <summary>The head's time, as it appears on the wire.</summary>
    public DateTime TimeName => Head.TimeName;

    /// <summary>The current key's public key, in the encoding the Zero Protocol transmits.</summary>
    public byte[] SubjectPublicKeyInfo => Head.Spki.ToArray();

    /// <summary>The key that signs (revealed by <see cref="Head"/>).</summary>
    public ECDsa CurrentKey => _keys[Head.Seq] ?? throw new InvalidOperationException( "The current key is unknown." );

    /// <summary>The committed next key: what a rotation reveals.</summary>
    public ECDsa NextKey => _keys[Head.Seq + 1] ?? throw new InvalidOperationException( "The next key is unknown." );

    /// <summary>
    /// The operational credential issued by the current key: what signs the transcript.
    /// </summary>
    public PeerCredential Credential => _credential ??= PeerCredential.Issue( CurrentKey, FullName );

    /// <summary>The digest of the head, which is what a pin statement about this peer states.</summary>
    public byte[] HeadDigest => Head.GetDigest( FullName ).ToArray();

    /// <summary>
    /// Rotates: reveals the committed next key and commits to a new one.
    /// </summary>
    public void Rotate( DateTime? timeName = null )
    {
        _credential?.Dispose();
        _credential = null;
        var next = NextKey;
        _keys.Add( NewKey() );
        _events.Add( KeyEvent.Create( FullName, Head.Seq + 1, timeName ?? DateTime.UtcNow, next, Commit( _keys[^1]! ), Head ) );
    }

    /// <summary>
    /// Ends this identity: reveals the committed next key with no further commitment.
    /// </summary>
    public void Abandon( DateTime? timeName = null )
    {
        _credential?.Dispose();
        _credential = null;
        _events.Add( KeyEvent.Create( FullName, Head.Seq + 1, timeName ?? DateTime.UtcNow, NextKey, ReadOnlySpan<byte>.Empty, Head ) );
    }

    /// <summary>
    /// Signs a hash with the current key, in the format the protocol expects (IEEE P1363, r‖s).
    /// </summary>
    public byte[] SignHash( ReadOnlySpan<byte> hash ) => CurrentKey.SignHash( hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );

    public void Dispose()
    {
        _credential?.Dispose();
        if( _ownsKeys ) foreach( var k in _keys ) k?.Dispose();
    }

    static ECDsa NewKey() => ECDsa.Create( ECCurve.NamedCurves.nistP256 );

    static byte[] Commit( ECDsa k ) => KeyEvent.ComputeCommit( k.ExportSubjectPublicKeyInfo() );
}

/// <summary>
/// What a sender states it pins for the receiver: a sequence of the receiver's log and that event's digest.
/// </summary>
public sealed record PeerStatement( int Seq, byte[] Digest );

/// <summary>
/// The harness's ephemeral ECDH key pair for one connection, mirroring what a real peer creates
/// per <c>Transport</c>. Exists so an adversarial test can also present a WRONG or reused
/// ephemeral, which a real peer never would.
/// </summary>
public sealed class PeerEphemeral : IDisposable
{
    readonly ECDiffieHellman _key;

    public PeerEphemeral()
    {
        _key = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        PublicKey = _key.PublicKey.ExportSubjectPublicKeyInfo();
    }

    /// <summary>The public half, as it travels on the wire.</summary>
    public byte[] PublicKey { get; }

    /// <summary>The key pair, for deriving the session when the harness needs to speak the run phase.</summary>
    public ECDiffieHellman Key => _key;

    public void Dispose() => _key.Dispose();
}
