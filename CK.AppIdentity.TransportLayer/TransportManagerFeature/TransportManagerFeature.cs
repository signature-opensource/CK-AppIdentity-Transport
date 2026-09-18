using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

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
    int _maxFlapReconnectDelay;
    TimeSpan _stableConnectionTime;
    TimeSpan _keepAliveIdleTime;
    TimeSpan _keepAliveProbeInterval;
    int _keepAliveProbeCount;
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
        _maxFlapReconnectDelay = 30;
        _stableConnectionTime = TimeSpan.FromMinutes( 1 );
        _keepAliveIdleTime = TimeSpan.FromSeconds( 30 );
        _keepAliveProbeInterval = TimeSpan.FromSeconds( 5 );
        _keepAliveProbeCount = 3;
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
    /// Gets or sets how long a connection may receive nothing before we ask the remote whether it is
    /// still there. Defaults to 30 seconds. <see cref="TimeSpan.Zero"/> disables keep-alive entirely.
    /// <para>
    /// Without this, a connection that dies without saying so — peer power loss, a NAT table entry
    /// expiring, a cable — stays <see cref="ConnectionAvailability.Connected"/> for ever. Writes into
    /// a half-open socket keep succeeding into the kernel buffer, so the send side does not notice
    /// either; what notices is the absence of an answer.
    /// </para>
    /// <para>
    /// The probe and its acknowledgment are Zero Protocol messages, so in the run phase they carry a
    /// MAC like every other frame: a peer that cannot authenticate cannot hold a dead link open.
    /// </para>
    /// </summary>
    public TimeSpan KeepAliveIdleTime
    {
        get => _keepAliveIdleTime;
        set
        {
            Throw.CheckOutOfRangeArgument( value >= TimeSpan.Zero );
            _keepAliveIdleTime = value;
        }
    }

    /// <summary>
    /// Gets or sets how long to wait for an answer before probing again. Defaults to 5 seconds,
    /// must be strictly positive.
    /// </summary>
    public TimeSpan KeepAliveProbeInterval
    {
        get => _keepAliveProbeInterval;
        set
        {
            Throw.CheckOutOfRangeArgument( value > TimeSpan.Zero );
            _keepAliveProbeInterval = value;
        }
    }

    /// <summary>
    /// Gets or sets how many unanswered probes condemn the connection. Defaults to 3, must be at
    /// least 1.
    /// <para>
    /// More than one on purpose: a single lost frame must not kill a healthy connection on the sort
    /// of link these parties run over.
    /// </para>
    /// </summary>
    public int KeepAliveProbeCount
    {
        get => _keepAliveProbeCount;
        set
        {
            Throw.CheckOutOfRangeArgument( value >= 1 );
            _keepAliveProbeCount = value;
        }
    }

    /// <summary>
    /// Gets or sets the longest delay, in heartbeats, between two reconnection attempts to a remote
    /// that keeps accepting us and then dropping us. Defaults to 30, must be between 1 and
    /// <see cref="BackTask{THost}.MaxCheckDelay"/>.
    /// <para>
    /// Failing to <em>connect</em> is cheap — nothing is negotiated — and keeps its own shorter
    /// back-off. This one covers the expensive case: a peer that accepts, negotiates and then drops
    /// us costs two signatures and two verifications per side, every cycle.
    /// </para>
    /// </summary>
    public int MaxFlapReconnectDelay
    {
        get => _maxFlapReconnectDelay;
        set
        {
            Throw.CheckOutOfRangeArgument( value >= 1 && value <= BackTask<TransportManager>.MaxCheckDelay );
            _maxFlapReconnectDelay = value;
        }
    }

    /// <summary>
    /// Gets or sets how long a connection must last before it stops counting as one more turn of a
    /// flap and resets <see cref="TransportFeature.FlapCount"/>. Defaults to one minute, must be
    /// strictly positive.
    /// </summary>
    public TimeSpan StableConnectionTime
    {
        get => _stableConnectionTime;
        set
        {
            Throw.CheckOutOfRangeArgument( value > TimeSpan.Zero );
            _stableConnectionTime = value;
        }
    }

    /// <summary>
    /// Gets or sets how many incoming connections may be negotiating at once. Defaults to 64,
    /// must be between 1 and 10000.
    /// <para>
    /// Everything an incoming connection costs before it has authenticated — a pooled buffer, a task,
    /// a back task, an SPKI import and an ECDSA verification — is spent on an unauthenticated peer's
    /// say-so. Beyond this many in flight, new connections are closed without being read.
    /// </para>
    /// </summary>
    public int MaxConcurrentNegotiation
    {
        get => _transportManager.NegotiationGate.MaxTotal;
        set => _transportManager.NegotiationGate.MaxTotal = value;
    }

    /// <summary>
    /// Gets or sets how many incoming connections may be negotiating at once from a single source
    /// address. Defaults to 16, must be between 1 and 10000.
    /// <para>
    /// This is what stops one peer from occupying every slot of <see cref="MaxConcurrentNegotiation"/>.
    /// Raise it when many legitimate parties share one address — several local parties on one host, or
    /// a NAT gateway in front of a fleet — since they cannot be told apart here.
    /// </para>
    /// </summary>
    public int MaxConcurrentNegotiationPerSource
    {
        get => _transportManager.NegotiationGate.MaxPerSource;
        set => _transportManager.NegotiationGate.MaxPerSource = value;
    }

    /// <summary>
    /// Gets how many incoming connections are currently negotiating.
    /// </summary>
    public int CurrentNegotiationCount => _transportManager.NegotiationGate.Count;

    /// <summary>
    /// Gets how many incoming connections have been refused by admission control since the start.
    /// A number that keeps climbing is either an attack or a <see cref="MaxConcurrentNegotiation"/>
    /// set below what this deployment legitimately needs.
    /// </summary>
    public long RefusedNegotiationCount => _transportManager.NegotiationGate.TotalRefused;

    /// <summary>
    /// Gets a snapshot of the peering issues. Issues are dynamic, they can be updated at any time.
    /// <para>
    /// Use <see cref="GetClonedPeeringIssues"/> for a non dynamic snapshot: an array of immutable <see cref="PeeringIssue.Clone"/> is returned.
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
    /// Gets the current number of issues for truly unknown remotes, the ones capped
    /// by <see cref="MaxUnknownRemoteCount"/>.
    /// <para>
    /// This is derived rather than tracked. A hand-maintained counter was incremented for each
    /// new unknown remote but not decremented for the entries the very same call trimmed, so it
    /// drifted upwards on every trim and the cap collapsed to one: each new unknown remote
    /// flushed every other one. An unauthenticated peer sending random full names could erase
    /// the operator's diagnostics at will. Counting at most <see cref="MaxUnknownRemoteCount"/>
    /// plus the known remotes is not worth a counter that can lie.
    /// </para>
    /// </summary>
    public int UnknownRemoteCount
    {
        get
        {
            lock( _peeringIssues )
            {
                return CountUnknownRemotes();
            }
        }
    }

    // Writes all happen on the TransportManager loop: callers already on the loop don't need
    // the lock (they enumerate _peeringIssues the same way), only concurrent readers do.
    int CountUnknownRemotes()
    {
        int c = 0;
        foreach( var i in _peeringIssues.Values )
        {
            if( i.Remote == null ) ++c;
        }
        return c;
    }

    /// <summary>
    /// Tries to find the <see cref="PeeringIssue"/> by its <see cref="PeeringIssue.FullName"/>.
    /// </summary>
    /// <param name="fullName">The party's full name to lookup.</param>
    /// <returns>The issue or null if this party has no issue.</returns>
    public PeeringIssue? Find( string fullName )
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
                monitor.Warn( ActivityMonitor.Tags.ToBeInvestigated,
                              $"Transport available for an existing PeeringIssue with no available Remote." );
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
            OnRemoteAppeared( issue, remote );
            return _peeringIssueChanged.SafeRaiseAsync( monitor, issue );
        }
        return Task.CompletedTask;
    }

    void OnRemoteTornDown( PeeringIssue issue )
    {
        // The issue either disappears or survives with a null Remote: either way
        // UnknownRemoteCount follows from the dictionary, there is nothing to maintain here.
        if( issue.OnRemoteTornDown() )
        {
            // Under the lock like every other mutation: readers (Find, GetPeeringIssues,
            // UnknownRemoteCount) can run on any thread.
            lock( _peeringIssues )
            {
                _peeringIssues.Remove( issue.FullName );
            }
            _exposedIssues = null;
        }
        _exposedClonedIssues = null;
    }

    void OnRemoteAppeared( PeeringIssue issue, TransportFeature remote )
    {
        issue.OnRemoteAppeared( remote );
        _exposedClonedIssues = null;
    }

    internal Task AddOrUpdateIssueAsync( IActivityMonitor monitor,
                                         PeeringIssueKind kind,
                                         InitialMessage? message,
                                         TransportFeature? remote,
                                         string? enlistUrl,
                                         bool enlistUrlIsAuthenticated,
                                         TimeSpan? invalidClockOffset,
                                         RemoteIdentityKeyData? remoteKeyForApproval,
                                         IReadOnlyList<string>? localMissing,
                                         IReadOnlyList<string>? remoteMissing,
                                         GoodbyeMessage? remoteOffMessage )
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
                if( remote != null ) OnRemoteAppeared( exist, remote );
                else OnRemoteTornDown( exist );
            }
            exist.Update( kind,
                            _transportManager.SystemClock.UtcNow,
                            message,
                            remote,
                            enlistUrl,
                            enlistUrlIsAuthenticated,
                            invalidClockOffset,
                            remoteKeyForApproval,
                            localMissing,
                            remoteMissing,
                            remoteOffMessage );
            _exposedClonedIssues = null;
            return _peeringIssueChanged.SafeRaiseAsync( monitor, exist );
        }
        // If there is no remote then cleanup in excess unknwon remotes if any
        // before adding the new one.
        if( remote == null )
        {
            // +1 for the one about to be added: end up with at most _maxUnknownRemoteCount.
            int inExcess = CountUnknownRemotes() + 1 - _maxUnknownRemoteCount;
            if( inExcess > 0 )
            {
                return AddNewUnknownAndTrimExcessAsync( monitor,
                                                        fullName,
                                                        kind,
                                                        message,
                                                        enlistUrl,
                                                        enlistUrlIsAuthenticated,
                                                        invalidClockOffset,
                                                        remoteKeyForApproval,
                                                        localMissing,
                                                        remoteMissing,
                                                        inExcess );
            }
        }
        _exposedClonedIssues = null;
        return AddNewPeeringIssueAsync( monitor,
                                        fullName,
                                        kind,
                                        message,
                                        remote,
                                        enlistUrl,
                                        enlistUrlIsAuthenticated,
                                        invalidClockOffset,
                                        remoteKeyForApproval,
                                        localMissing,
                                        remoteMissing );
    }

    async Task AddNewUnknownAndTrimExcessAsync( IActivityMonitor monitor,
                                                NormalizedPath fullName,
                                                PeeringIssueKind kind,
                                                InitialMessage? message,
                                                string? enlistUrl,
                                                bool enlistUrlIsAuthenticated,
                                                TimeSpan? invalidClockOffset,
                                                RemoteIdentityKeyData? remoteKeyForApproval,
                                                IReadOnlyList<string>? localMissingProtocols,
                                                IReadOnlyList<string>? remoteMissingProtocols,
                                                int inExcess )
    {
        // Oldest first: the point of the cap is to keep what is still relevant. Ordering by
        // descending LastUpdated evicted the freshest diagnostics and kept the stalest ones.
        var toRemove = _peeringIssues.Values.Where( i => i.Remote == null )
                                            .OrderBy( i => i.LastUpdated )
                                            .Take( inExcess )
                                            .ToArray();
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
        await AddNewPeeringIssueAsync( monitor,
                                       fullName,
                                       kind,
                                       message,
                                       null,
                                       enlistUrl,
                                       enlistUrlIsAuthenticated,
                                       invalidClockOffset,
                                       remoteKeyForApproval,
                                       localMissingProtocols,
                                       remoteMissingProtocols );
    }

    Task AddNewPeeringIssueAsync( IActivityMonitor monitor,
                                  NormalizedPath fullName,
                                  PeeringIssueKind kind,
                                  InitialMessage? message,
                                  TransportFeature? remote,
                                  string? enlistUrl,
                                  bool enlistUrlIsAuthenticated,
                                  TimeSpan? invalidClockOffset,
                                  RemoteIdentityKeyData? remoteKeyForApproval,
                                  IReadOnlyList<string>? localMissingProtocols,
                                  IReadOnlyList<string>? remoteMissingProtocols )
    {
        // Add the new issue.
        var issue = new PeeringIssue( fullName,
                                      _transportManager.ApplicationIdentityAgent.ApplicationIdentityService.SystemClock.UtcNow,
                                      kind,
                                      message,
                                      remote,
                                      enlistUrl,
                                      enlistUrlIsAuthenticated,
                                      invalidClockOffset,
                                      remoteKeyForApproval,
                                      localMissingProtocols,
                                      remoteMissingProtocols );
        lock( _peeringIssues )
        {
            _peeringIssues.Add( fullName, issue );
        }
        _exposedIssues = null;
        return _peeringIssueChanged.SafeRaiseAsync( monitor, issue );
    }
}
