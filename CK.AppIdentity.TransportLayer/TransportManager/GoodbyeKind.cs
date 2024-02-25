namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// There are 4 of soft condemnations.
    /// </summary>
    public enum GoodbyeKind
    {
        /// <summary>
        /// The <see cref="TransportFeature.DisallowEviction"/> is false (the default): a listener has
        /// accepted a new valid connection from another instance.
        /// </summary>
        Evicted,

        /// <summary>
        /// The <see cref="TransportFeature.SwitchOff(string)"/> has been called.
        /// </summary>
        SwitchedOff,

        /// <summary>
        /// The party has been destroyed.
        /// </summary>
        PartyDestroyed,

        /// <summary>
        /// The whole <see cref="ApplicationIdentityService"/> is being disposed.
        /// </summary>
        ApplicationIdentityShutdown
    }
}
