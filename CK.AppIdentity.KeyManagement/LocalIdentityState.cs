using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The current identity of a local party, as one consistent snapshot: the key that signs and the
/// tail of the key event log that proves it is current.
/// <para>
/// A rotation replaces the whole snapshot at once. Reading the key and the tail separately could pair
/// a tail with a key of another rotation, and a peer would refuse the message.
/// </para>
/// </summary>
public sealed class LocalIdentityState
{
    readonly LocalIdentityKey[] _identities;
    readonly KeyEvent[] _log;
    readonly KeyEvent[] _tail;

    internal LocalIdentityState( LocalIdentityKey key, KeyEvent[] log )
    {
        _identities = [key];
        _log = log;
        _tail = log.Length <= KeyEventChain.MaxEventTail ? log : log[^KeyEventChain.MaxEventTail..];
    }

    /// <summary>
    /// Gets the identity key that signs.
    /// </summary>
    public LocalIdentityKey Key => _identities[0];

    /// <summary>
    /// Gets the head of the log: the event that reveals <see cref="Key"/>.
    /// </summary>
    public KeyEvent Head => _log[^1];

    /// <summary>
    /// Gets the last events of the log (at most <see cref="KeyEventChain.MaxEventTail"/>), oldest first.
    /// </summary>
    public IReadOnlyList<KeyEvent> Tail => _tail;

    /// <summary>
    /// Gets an event of the log by its sequence number. The log is complete from the inception.
    /// </summary>
    /// <param name="seq">The sequence number.</param>
    /// <returns>The event, or null when <paramref name="seq"/> is beyond the head or negative.</returns>
    public KeyEvent? GetEvent( int seq ) => seq >= 0 && seq < _log.Length ? _log[seq] : null;

    /// <summary>
    /// Gets the whole log, from the inception.
    /// </summary>
    internal KeyEvent[] Log => _log;

    /// <summary>
    /// Gets the one-element list of <see cref="ILocalKeys.Identities"/>: one instance per snapshot, so
    /// that a rotation is detected by reference.
    /// </summary>
    internal LocalIdentityKey[] Identities => _identities;
}
