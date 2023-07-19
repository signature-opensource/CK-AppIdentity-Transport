using CK.Core;
using CK.PerfectEvent;
using System.Collections.Immutable;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Root feature (available in <see cref="ApplicationIdentityService.Features"/>).
    /// </summary>
    public sealed class TransportManagerFeature
    {
        readonly TransportManager _transportManager;

        // This relay events of all the TransportFeatures.
        internal readonly PerfectEventSender<TransportFeature> _connectionAvailabilityChanged;

        // This is raised first by the ApplicationIdentityAgent when creating a feature
        // and then by the TransportManager on SwitchOff/SwitchOn. 
        internal readonly PerfectEventSender<TransportFeature> _transportFeatureChangedEvent;

        // Raised on new event.
        readonly PerfectEventSender<PeeringIssue> _peeringIssueChanged;
        readonly Dictionary<string, PeeringIssue> _peeringIssues;
        int _maxUnknownRemoteCount;
        int _unknwonRemoteCount;
        PeeringIssue[]? _exposedIssues;

        internal TransportManagerFeature( TransportManager transportManager )
        {
            _connectionAvailabilityChanged = new PerfectEventSender<TransportFeature>();
            _transportFeatureChangedEvent = new PerfectEventSender<TransportFeature>();
            _peeringIssueChanged = new PerfectEventSender<PeeringIssue>();
            _peeringIssues = new Dictionary<string, PeeringIssue>();
            _transportManager = transportManager;
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

        /// <summary>
        /// Gets or sets the maximal number of memorized <see cref="PeeringIssue"/> for truly unknwon remotes
        /// (when <see cref="PeeringIssue.Remote"/> is null).
        /// Must be between 5 and 100, defaults to 5.
        /// </summary>
        public int MaxUnknownRemoteCount
        {
            get => _maxUnknownRemoteCount;
            set
            {
                Throw.CheckOutOfRangeArgument( value >= 5 && value <= 100 );
                _maxUnknownRemoteCount = value;
            }
        }

        /// <summary>
        /// Gets a snapshot of the peering issues.
        /// This is a dynamic set that can be updated at any time. 
        /// </summary>
        public PeeringIssue[] GetPeeringIssues()
        {
            var r = _exposedIssues;
            if( r == null  )
            {
                lock( _peeringIssues )
                {
                    r ??= _exposedIssues = _peeringIssues.Values.ToArray();
                }
            }
            return r;
        }

        /// <summary>
        /// Raised when a new <see cref="PeeringIssue"/> appears. 
        /// </summary>
        public PerfectEvent<PeeringIssue> EventAppeared => _peeringIssueChanged.PerfectEvent;

        internal Task AddOrUpdateIssueAsync( IActivityMonitor monitor,
                                             PeeringIssueKind kind,
                                             InitialMessage? message,
                                             TransportFeature? remote,
                                             string? enlistUrl,
                                             TimeSpan? invalidClockOffset )
        {
            // Use the remote (long-living) full name if possible.
            var fullName = remote?.Party.FullName ?? message!.FullName;
            if( _peeringIssues.TryGetValue( fullName, out var exist ) )
            {
                // Updates the existing issue and removes it from the dictionary if it's now None.
                exist.Update( kind, _transportManager.SystemClock.UtcNow, message, remote, enlistUrl, invalidClockOffset, ref _unknwonRemoteCount );
                if( kind == PeeringIssueKind.None )
                {
                    lock( _peeringIssues )
                    {
                        _peeringIssues.Remove( fullName );
                    }
                    _exposedIssues = null;
                }
            }
            else
            {
                if( kind == PeeringIssueKind.None )
                {
                    // This should not happen (defensive programming).
                    return Task.CompletedTask;
                }
                // If there is no remote then cleaup in excess unknwon if any
                // before adding the new one.
                if( remote == null )
                {
                    int inExcess = ++_unknwonRemoteCount - _maxUnknownRemoteCount;
                    if( inExcess > 0 )
                    {
                        var toRemove = _peeringIssues.Values.Where( i => i.Remote == null ).OrderByDescending( i => i.LastUpdated ).Take( inExcess ).ToArray();
                        monitor.Info( $"Removing peering issues for unknown remotes: '{toRemove.Select( i => i.FullName ).Concatenate( "', '")}'. Max {_maxUnknownRemoteCount} has been reached." );
                        lock( _peeringIssues )
                        {
                            foreach( var i in toRemove ) _peeringIssues.Remove( i.FullName );
                        }
                        _exposedIssues = null;
                    }
                }
                // Add the new issue.
                exist = new PeeringIssue( fullName,
                                          _transportManager.ApplicationIdentityAgent.ApplicationIdentityService.SystemClock.UtcNow,
                                          kind,
                                          message,
                                          remote,
                                          enlistUrl,
                                          invalidClockOffset );
                lock( _peeringIssues )
                {
                    _peeringIssues.Add( fullName, exist );
                }
                _exposedIssues = null;
            }
            return _peeringIssueChanged.SafeRaiseAsync( monitor, exist );
        }
    }
}
