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
        // This is raised by the TransportManager.
        internal readonly PerfectEventSender<TransportFeatureChangedEvent> _transportFeatureChangedEvent;

        internal TransportManagerFeature()
        {
            _connectionAvailabilityChanged = new PerfectEventSender<TransportFeature>();
            _transportFeatureChangedEvent = new PerfectEventSender<TransportFeatureChangedEvent>();
        }

        /// <summary>
        /// Raised when a <see cref="TransportFeature"/> appears, disappears or
        /// its <see cref="TransportFeature.IsOff"/> changes. 
        /// </summary>
        public PerfectEvent<TransportFeatureChangedEvent> TransportChanged => _transportFeatureChangedEvent.PerfectEvent;

        /// <summary>
        /// Raised when a <see cref="TransportFeature.ConnectionAvailability"/> changes. 
        /// </summary>
        public PerfectEvent<TransportFeature> ConnectionAvailabilityChanged => _connectionAvailabilityChanged.PerfectEvent;
    }
}
