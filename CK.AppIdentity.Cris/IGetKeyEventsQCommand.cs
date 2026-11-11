using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Asks a party its key events, from the point of its log that the sender holds (its trust anchor of it, or the head it
/// holds): sent along a route hosted by the party (see <see cref="AnchoredKeyDirectory"/>). The destination answers with
/// its own events, from <see cref="FromSeq"/> up to <see cref="KeyManagement.KeyEventChain.MaxEventWindow"/> events (its
/// last events when <see cref="FromSeq"/> is null or out of the window). Key events are public: any party of the System
/// can ask. What comes back is verified by the sender, never believed: a hop can withhold it, not forge it.
/// </summary>
[Internal]
public interface IGetKeyEventsQCommand : ICommand<IPartyKeyEvents>
{
    /// <summary>
    /// Gets or sets the sequence from which the events are needed.
    /// </summary>
    int? FromSeq { get; set; }
}

/// <summary>
/// The key events of a party (see <see cref="IGetKeyEventsQCommand"/>).
/// </summary>
public interface IPartyKeyEvents : IPoco
{
    /// <summary>
    /// Gets the full name of the party that answered.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the encoded events (see <see cref="KeyManagement.KeyEvent.Encoded"/>), consecutive, oldest first.
    /// <para>
    /// An array of arrays: a collection of a poco property can't contain another collection (an <c>IList&lt;byte[]&gt;</c>
    /// is refused by the engine), arrays of arrays are allowed.
    /// </para>
    /// </summary>
    byte[][] Events { get; set; }
}
