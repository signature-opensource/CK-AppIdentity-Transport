namespace CK.AppIdentity.TransportLayer
{
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
        /// The calling remote is either totally unknown (<see cref="PeeringIssue.Remote"/> is null) or
        /// is not yet trusted (it can be accepetd by calling <see cref="PeeringIssue.AcceptRemoteIdentity(Core.IActivityMonitor)"/>.
        /// <para>
        /// This applies only to listeners.
        /// </para>
        /// </summary>
        IncomingRequest,

        /// <summary>
        /// The target remote is not trusting us yet. If <see cref="PeeringIssue.EnlistUrl"/> is not null, it
        /// can be used by an authorized user of the remote system to allow us.
        /// <para>
        /// This applies only to initiators.
        /// </para>
        /// </summary>
        WaitingRemoteApproval


    }

}
