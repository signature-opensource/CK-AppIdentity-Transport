using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

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
        PeeringIssue[]? _exposedClonedIssues;

        internal TransportManagerFeature( TransportManager transportManager )
        {
            _connectionAvailabilityChanged = new PerfectEventSender<TransportFeature>();
            _transportFeatureChangedEvent = new PerfectEventSender<TransportFeature>();
            _peeringIssueChanged = new PerfectEventSender<PeeringIssue>();
            _peeringIssues = new Dictionary<string, PeeringIssue>();
            _transportManager = transportManager;
            _maxUnknownRemoteCount = 5;
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
        /// (for <see cref="PeeringIssue.IsListener"/>: <see cref="PeeringIssue.Remote"/> is null).
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
        /// Gets a snapshot of the peering issues. Issues are dynamic, they can be updated at any time.
        /// <para>
        /// Use <see cref="GetClonedPeeringIssues"/> for a non dynamic snapshot: an array of immutable <see cref="Clone"/> is returned.
        /// </para>
        /// </summary>
        /// <returns>An array containing the current issues.</returns>
        public PeeringIssue[] GetPeeringIssues()
        {
            var r = _exposedIssues;
            if( r == null )
            {
                lock( _peeringIssues )
                {
                    r = _exposedIssues ??= _peeringIssues.Values.ToArray();
                }
            }
            return r;
        }

        /// <summary>
        /// Gets the current number of peering issues.
        /// </summary>
        public int IssueCount => _peeringIssues.Count;

        /// <summary>
        /// Tries to find the <see cref="PeeringIssue"/> by its <see cref="PeeringIssue.FullName"/>.
        /// </summary>
        /// <param name="fullName">The party's full name to lookup.</param>
        /// <returns>The issue or null if this party has no issue.</returns>
        public PeeringIssue? Find(  string fullName )
        {
            lock( _peeringIssues )
            {
                return _peeringIssues.GetValueOrDefault( fullName );
            }
        }

        /// <summary>
        /// Gets a snapshot of the peering issues. Returned issues are immutable <see cref="Clone"/>.
        /// </summary>
        /// <returns>An array containing the cloned issues.</returns>
        public PeeringIssue[] GetClonedPeeringIssues()
        {
            var r = _exposedClonedIssues;
            if( r == null )
            {
                lock( _peeringIssues )
                {
                    r = _exposedClonedIssues;
                    if( r == null )
                    {
                        var cloned = new PeeringIssue[_peeringIssues.Count];
                        int i = 0;
                        foreach( var issue in _peeringIssues.Values )
                        {
                            cloned[i++] = issue.Clone();
                        }
                        r = _exposedClonedIssues = cloned;
                    }
                }
            }
            return r;
        }

        /// <summary>
        /// Raised when a new <see cref="PeeringIssue"/> appears, disappears or is updated.
        /// The <see cref="PeeringIssue.Kind"/> is <see cref="PeeringIssueKind.None"/> when disappearing.
        /// </summary>
        public PerfectEvent<PeeringIssue> PeeringIssueChanged => _peeringIssueChanged.PerfectEvent;

        internal Task OnTransportAvailableAsync( IActivityMonitor monitor, TransportFeature remote )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            if( _peeringIssues.TryGetValue( remote.Party.FullName, out var issue ) )
            {
                if( issue.Remote == null )
                {
                    // This should not happen!
                    monitor.Warn( ActivityMonitor.Tags.ToBeInvestigated, $"Transport available for an existing PeeringIssue with no available Remote." );
                    --_unknwonRemoteCount;
                }
                issue.SetNoneIssueKind();
                lock( _peeringIssues )
                {
                    _peeringIssues.Remove( issue.FullName );
                }
                _exposedIssues = null;
                _exposedClonedIssues = null;
                return _peeringIssueChanged.SafeRaiseAsync( monitor, issue );
            }
            return Task.CompletedTask;
        }

        internal Task OnRemoteTornDownAsync( IActivityMonitor monitor, TransportFeature remote )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            if( _peeringIssues.TryGetValue( remote.Party.FullName, out var issue ) && issue.Remote != null )
            {
                OnRemoteTornDown( issue );
                return _peeringIssueChanged.SafeRaiseAsync( monitor, issue );
            }
            return Task.CompletedTask;
        }

        internal Task OnRemoteAppearedAsync( IActivityMonitor monitor, TransportFeature remote )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            if( _peeringIssues.TryGetValue( remote.Party.FullName, out var issue ) && issue.Remote == null )
            {
                OnRemoteAppeared( remote, issue );
                return _peeringIssueChanged.SafeRaiseAsync( monitor, issue );
            }
            return Task.CompletedTask;
        }

        void OnRemoteTornDown( PeeringIssue issue )
        {
            if( issue.OnRemoteTornDown() )
            {
                _peeringIssues.Remove( issue.FullName );
                _exposedIssues = null;
            }
            else
            {
                _unknwonRemoteCount++;
            }
            _exposedClonedIssues = null;
        }

        void OnRemoteAppeared( TransportFeature remote, PeeringIssue issue )
        {
            _unknwonRemoteCount--;
            issue.OnRemoteAppeared( remote );
            _exposedClonedIssues = null;
        }

        internal Task AddOrUpdateIssueAsync( IActivityMonitor monitor,
                                             PeeringIssueKind kind,
                                             InitialMessage? message,
                                             TransportFeature? remote,
                                             string? enlistUrl,
                                             TimeSpan? invalidClockOffset )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            Throw.DebugAssert( kind != PeeringIssueKind.None );

            // Use the remote (long-living) full name if possible.
            var fullName = remote?.Party.FullName ?? message!.FullName;
            if( _peeringIssues.TryGetValue( fullName, out var exist ) )
            {
                // First, handles the case where remote appeared/disappeared without
                // OnRemoteTornDown/OnRemoteAppeared calls: this is a race condition
                // that can happen since the destruction and creation of remotes don't
                // use lock.
                if( (exist.Remote == null) != (remote == null) )
                {
                    if( remote != null ) OnRemoteAppeared( remote, exist );
                    else OnRemoteTornDown( exist );
                }
                if( exist.Kind != PeeringIssueKind.None )
                {
                    exist.Update( kind, _transportManager.SystemClock.UtcNow, message, remote, enlistUrl, invalidClockOffset );
                    _exposedClonedIssues = null;
                }
                return _peeringIssueChanged.SafeRaiseAsync( monitor, exist );
            }
            // If there is no remote then cleanup in excess unknwon remotes if any
            // before adding the new one.
            if( remote == null )
            {
                int inExcess = ++_unknwonRemoteCount - _maxUnknownRemoteCount;
                if( inExcess > 0 )
                {
                    return AddNewUnknownAndTrimExcess( monitor, kind, message, enlistUrl, invalidClockOffset, fullName, inExcess );
                }
            }
            _exposedClonedIssues = null;
            return AddNewPeeringIssue( monitor, kind, message, remote, enlistUrl, invalidClockOffset, fullName );
        }

        async Task AddNewUnknownAndTrimExcess( IActivityMonitor monitor,
                                               PeeringIssueKind kind,
                                               InitialMessage? message,
                                               string? enlistUrl,
                                               TimeSpan? invalidClockOffset,
                                               NormalizedPath fullName,
                                               int inExcess )
        {
            var toRemove = _peeringIssues.Values.Where( i => i.Remote == null ).OrderByDescending( i => i.LastUpdated ).Take( inExcess ).ToArray();
            monitor.Info( $"Removing peering issues for unknown remotes: '{toRemove.Select( i => i.FullName ).Concatenate( "', '" )}'. Max {_maxUnknownRemoteCount} has been reached." );
            lock( _peeringIssues )
            {
                foreach( var i in toRemove ) _peeringIssues.Remove( i.FullName );
            }
            _exposedIssues = null;
            foreach( var i in toRemove )
            {
                i.SetNoneIssueKind();
                await _peeringIssueChanged.SafeRaiseAsync( monitor, i );
            }
            _exposedClonedIssues = null;
            await AddNewPeeringIssue( monitor, kind, message, null, enlistUrl, invalidClockOffset, fullName );
        }

        Task AddNewPeeringIssue( IActivityMonitor monitor,
                                 PeeringIssueKind kind,
                                 InitialMessage? message,
                                 TransportFeature? remote,
                                 string? enlistUrl,
                                 TimeSpan? invalidClockOffset,
                                 NormalizedPath fullName )
        {
            // Add the new issue.
            var issue = new PeeringIssue( fullName,
                                          _transportManager.ApplicationIdentityAgent.ApplicationIdentityService.SystemClock.UtcNow,
                                          kind,
                                          message,
                                          remote,
                                          enlistUrl,
                                          invalidClockOffset );
            lock( _peeringIssues )
            {
                _peeringIssues.Add( fullName, issue );
            }
            _exposedIssues = null;
            return _peeringIssueChanged.SafeRaiseAsync( monitor, issue );
        }
    }
}
