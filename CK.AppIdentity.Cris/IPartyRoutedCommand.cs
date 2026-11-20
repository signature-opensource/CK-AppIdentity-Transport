using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Carries a command (its <see cref="SealedCommand"/>) to a party of the System that is not a remote of the sender, along a path: each hop
/// forwards it to the next one (its <see cref="ICommandTargetParty.TargetPartyFullName"/> is the next hop, so the
/// channel's reception checks apply at each hop), only the destination executes the inner command, and its result comes
/// back by the chain of calls. Use the <see cref="PartyRoutedCommandSender"/> to send one.
/// <para>
/// The destination is the last party of the <see cref="Path"/>. A System is a star around its Authentication Center: a
/// path is [the origin, the hub, the destination] (see <see cref="IPartyRelay"/>), or the way back to the party a request
/// came from. There are no announced routes: nothing to hijack, only the hub relays and it knows every identity.
/// </para>
/// <para>
/// The originating party (the first of <see cref="Via"/>) is the caller party of the inner command: the
/// <see cref="ICrisChannelReceptionHandler"/> of the destination receives it (<see cref="CrisCallerParty"/>). Each hop
/// vouches for its predecessor only (the last of <see cref="Via"/> must be the remote that sent it): the destination
/// believes the chain, inside the System. The user's proof travels in the envelope.
/// </para>
/// <para>
/// The command travels as the exact bytes serialized by the originating party (<see cref="SealedCommand"/>): the hops
/// never read it, and the destination executes the command read from these bytes. An extension can bind them to the
/// origin: the authentication packages sign them with the user's proof (see <see cref="ICrisCallEnvelopeContributor"/>).
/// </para>
/// <para>
/// This is handled by the channels (<see cref="CrisChannelFeature"/>), never by a command handler. It never carries
/// another routed command, nor an endpoint-only one (its <see cref="IRemoteParty"/> would be the last hop).
/// </para>
/// </summary>
[Internal]
public interface IPartyRoutedCommand : ICommand<object?>, ICommandTargetParty
{
    /// <summary>
    /// Gets or sets the command to execute on the destination: the UTF-8 JSON of the command, with its type, serialized by
    /// the originating party with the exchange options of the channels. Set by the <see cref="PartyRoutedCommandSender"/>,
    /// read by the destination only.
    /// </summary>
    byte[]? SealedCommand { get; set; }

    /// <summary>
    /// Gets the full names of the parties from the originating one to the destination, both included.
    /// </summary>
    IList<string> Path { get; }

    /// <summary>
    /// Gets the full names of the parties this command went through, the originating one first: each hop adds itself
    /// before forwarding it.
    /// </summary>
    IList<string> Via { get; }

    /// <summary>
    /// Gets or sets the time the party that receives this command has to answer: its sender (the origin, then each hop)
    /// waits for the answer a little longer (see <see cref="PartyRoutedCommandSender"/>). A hop forwards it only when
    /// time is left (at most the <see cref="ChannelCrisRemoteDispatcher.Timeout"/>), with the time it has left minus a
    /// margin: its error (an unavailable next hop, no answer in time) reaches its sender before the sender gives up. The
    /// destination ignores it.
    /// </summary>
    TimeSpan TimeBudget { get; set; }
}
