using CK.PerfectEvent;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Root feature (available in <see cref="ApplicationIdentityService.Features"/>).
    /// </summary>
    public sealed class TransportManagerFeature
    {
        // This relay events of all the TransportFeatures.
        internal readonly PerfectEventSender<TransportFeature> _connectionAvailabilityChanged;
        // This is raised first by the ApplicationIdentityAgent when creating a feature
        // and then by the TransportManager on SwitchOff/SwitchOn. 
        internal readonly PerfectEventSender<TransportFeature> _transportFeatureChangedEvent;

        internal TransportManagerFeature()
        {
            _connectionAvailabilityChanged = new PerfectEventSender<TransportFeature>();
            _transportFeatureChangedEvent = new PerfectEventSender<TransportFeature>();
        }

        /// <summary>
        /// Raised when a <see cref="TransportFeature"/> appears, disappears or
        /// its <see cref="TransportFeature.IsOff"/> changes. 
        /// </summary>
        public PerfectEvent<TransportFeature> TransportChanged => _transportFeatureChangedEvent.PerfectEvent;

        /// <summary>
        /// Raised when a <see cref="TransportFeature.ConnectionAvailability"/> changes. 
        /// </summary>
        public PerfectEvent<TransportFeature> ConnectionAvailabilityChanged => _connectionAvailabilityChanged.PerfectEvent;
    }
}
