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
        /// The remote that is calling us is either totally unknown (<see cref="PeeringIssue.Remote"/> is null) or
        /// is not yet trusted (it can be accepetd by calling <see cref="PeeringIssue.AcceptRemoteIdentity(Core.IActivityMonitor)"/>.
        /// <para>
        /// This applies only to listeners.
        /// </para>
        /// </summary>
        UnknwonIncoming,

        /// <summary>
        /// A known remote is calling (<see cref="PeeringIssue.Remote"/> is not null) but we don't trusted it yet.
        /// It can be accepted by calling <see cref="PeeringIssue.AcceptRemoteIdentity(Core.IActivityMonitor)"/>.
        /// <para>
        /// This applies only to listeners.
        /// </para>
        /// </summary>
        UntrustedIncoming,

        /// <summary>
        /// The target remote knows us but is not trusting us yet. If <see cref="PeeringIssue.EnlistUrl"/> is not null, it
        /// can be used by an authorized user of the remote system to allow us.
        /// <para>
        /// This applies only to initiators.
        /// </para>
        /// </summary>
        WaitingRemoteApproval,

        /// <summary>
        /// The target remote doesn't know us at all. If <see cref="PeeringIssue.EnlistUrl"/> is not null, it
        /// can be used by an authorized user of the remote system to create (and allow) us.
        /// <para>
        /// This applies only to initiators.
        /// </para>
        /// </summary>
        WaitingRemoteCreation,

        /// <summary>
        /// Both us and the remote are initiators.
        /// </summary>
        InitiatorConflict
    }

}
