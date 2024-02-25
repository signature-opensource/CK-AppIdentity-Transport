namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Summarizes the 4 kind of <see cref="PeeringIssue"/>.
    /// </summary>
    public enum PeeringIssueKind
    {
        /// <summary>
        /// There is no (or no more) issue.
        /// </summary>
        None,

        /// <summary>
        /// The offset between this system and the remote one is bigger than <see cref="TransportFeature.MaxClockOffset"/>.
        /// Clocks must be synchronized before anything can be done.
        /// <para>
        /// This applies to listeners and initiators.
        /// </para>
        /// </summary>
        InvalidClockOffset,

        /// <summary>
        /// Both us and the remote are initiators.
        /// </summary>
        InitiatorConflict,

        /// <summary>
        /// The remote that is calling us is totally unknown (<see cref="PeeringIssue.FullName"/> is not one
        /// of our <see cref="ApplicationIdentityService.AllRemotes"/>).
        /// <para>
        /// This applies only to listeners.
        /// </para>
        /// </summary>
        IncomingUnknwon,

        /// <summary>
        /// The target remote doesn't know us at all. If <see cref="PeeringIssue.EnlistUrl"/> is not null, it
        /// may be used by an authorized user of the remote system to create (and allow) us.
        /// <para>
        /// This applies only to initiators (this mirrors <see cref="IncomingUnknwon"/>).
        /// </para>
        /// </summary>
        RequiresRemoteCreation,

        /// <summary>
        /// The remote that is calling us is known (the <see cref="IRemoteParty"/> exists) but its its <see cref="TransportFeature"/> is disallowed.
        /// <para>
        /// This applies only to listeners.
        /// </para>
        /// </summary>
        IncomingDisallowedTransport,

        /// <summary>
        /// The target knows us: our remote counterpart exists but its <see cref="TransportFeature"/> is disallowed.
        /// <para>
        /// This applies only to initiators (this mirrors <see cref="IncomingDisallowedTransport"/>).
        /// </para>
        /// </summary>
        RemoteDisallowedTransport,

        /// <summary>
        /// A known remote is calling (<see cref="PeeringIssue.Remote"/> is not null) but on a wrong Transport type
        /// or local address.
        /// <para>
        /// This applies only to listeners.
        /// </para>
        /// </summary>
        IncomingUnsupportedTransport,

        /// <summary>
        /// The target knows us: our remote counterpart exists but is listening on another type of transport or address.
        /// <para>
        /// This applies only to initiators (this mirrors <see cref="IncomingUnsupportedTransport"/>).
        /// </para>
        /// </summary>
        RemoteUnsupportedTransport,

        /// <summary>
        /// The remote transport feature is switched off.
        /// <para>
        /// This applies only to initiators.
        /// </para>
        /// </summary>
        RemoteIsSwitchedOff,

        /// <summary>
        /// The remote is already connected to another party with the same <see cref="IParty.FullName"/>
        /// and it is configured to disallow eviction.
        /// <para>
        /// This applies only to initiators.
        /// </para>
        /// </summary>
        RemoteDisallowEviction,

        /// <summary>
        /// The remote has been evicted by another party with the same <see cref="IParty.FullName"/>.
        /// <para>
        /// This applies only to initiators.
        /// </para>
        /// </summary>
        RemoteHasBeenEvicted,

        /// <summary>
        /// The remote trusts us but we don't trust it yet.
        /// It can be accepted by calling <see cref="PeeringIssue.AcceptRemoteIdentity(Core.IActivityMonitor)"/>.
        /// </summary>
        RequiresLocalApproval,

        /// <summary>
        /// We trust the remote but the remote doesn't trust us yet. If <see cref="PeeringIssue.EnlistUrl"/> is not null, it
        /// may be used by an authorized user of the remote system to allow us.
        /// </summary>
        RequiresRemoteApproval,

        /// <summary>
        /// The remote doesn't trust us and we don't trust it either.
        /// </summary>
        RequiresBothApproval,

        /// <summary>
        /// Trusted relationship has been estanblished but expected protocols are not satisfied:
        /// <see cref="PeeringIssue.LocalMissingProtocols"/> and <see cref="PeeringIssue.RemoteMissingProtocols"/> contain
        /// the culprits.
        /// </summary>
        MissingProtocols
    }

}
