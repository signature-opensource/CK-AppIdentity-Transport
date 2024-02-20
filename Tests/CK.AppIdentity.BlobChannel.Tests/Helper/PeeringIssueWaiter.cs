using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.BlobChannel.Tests
{
    /// <summary>
    /// Simple PeeringIssue awaiter. It is bound to the <see cref="TransportManagerFeature"/>
    /// and exposes the <see cref="NextEvent"/> that is a task that can be awaited.
    /// </summary>
    sealed class PeeringIssueWaiter : IDisposable
    {
        readonly TransportManagerFeature _transport;
        TaskCompletionSource<PeeringIssue> _nextEvent;
        PeeringIssue? _lastEvent;

        public PeeringIssueWaiter( TransportManagerFeature transport )
        {
            _transport = transport;
            _nextEvent = new TaskCompletionSource<PeeringIssue>();
            transport.PeeringIssueChanged.Sync += OnPeeringIssueChanged;
        }

        void OnPeeringIssueChanged( IActivityMonitor monitor, PeeringIssue e )
        {
            var n = _nextEvent;
            _nextEvent = new TaskCompletionSource<PeeringIssue>();
            n.SetResult( _lastEvent = e );
        }

        /// <summary>
        /// Stops listening to events.
        /// </summary>
        public void Dispose()
        {
            _transport.PeeringIssueChanged.Sync -= OnPeeringIssueChanged;
        }

        /// <summary>
        /// Gets the last received event.
        /// </summary>
        public PeeringIssue? LastEvent => _lastEvent;

        /// <summary>
        /// Gets a task that will be completed by the next PeeringIssue event.
        /// </summary>
        public Task<PeeringIssue> NextEvent => _nextEvent.Task;
    }
}
