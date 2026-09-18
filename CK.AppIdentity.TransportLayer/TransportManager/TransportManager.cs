using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// <see cref="MicroAgent"/> that manages the <see cref="Transport"/> remote's features.
/// <para>
/// This class is internal but exposes the public <see cref="TransportManagerFeature"/>.
/// </para>
/// </summary>
sealed partial class TransportManager : MicroAgent
{
    /// <summary>
    /// Maximal time in milliseconds an INCOMING connection may spend negotiating before it is killed.
    /// This delay is not based on the heartbeat rate.
    /// <para>
    /// This is a denial-of-service control, not a reachability budget: it bounds how long a stranger
    /// who has authenticated nothing holds one of the slots
    /// <see cref="TransportManagerFeature.MaxConcurrentNegotiation"/> counts. It is deliberately short,
    /// and deliberately NOT the same number as the outgoing side uses — see
    /// <see cref="TransportFeature.OutgoingNegotiationTimeout"/>. Raising this to suit a slow link
    /// would multiply what an unauthenticated peer can hold.
    /// </para>
    /// <para>
    /// The span it covers starts after the connection is accepted: reading the InitialMessage,
    /// verifying one signature, replying, and reading the final message — roughly one round trip.
    /// </para>
    /// </summary>
    public const int IncomingNegotiationTimeout = 2000;

    readonly AppIdentityAgent _agent;
    readonly MessageProtocolDirectoryService _protocolDirectory;
    readonly List<TransportListener> _listeners;
    readonly TransportManagerFeature _exposedFeature;
    readonly NegotiationGate _negotiationGate;

    // ApplicationIdentityService's heart beat handles the BackTask list.
    readonly BackTask<TransportManager>.BackTaskManager _backTasks;
    readonly BackTask<TransportManager>.Head _headIncomingConnection;
    readonly BackTask<TransportManager>.Head _headOutgoingConnection;
    readonly BackTask<TransportManager>.Head _headDelayedKillTransport;
    readonly BackTask<TransportManager>.Head _headKeepAlive;

    internal TransportManager( AppIdentityAgent agent, MessageProtocolDirectoryService protocolDirectory )
        : base( $"TransportManager for {agent.ApplicationIdentityService}", agent.SystemClock.HeatBeatPeriod )
    {
        _agent = agent;
        _protocolDirectory = protocolDirectory;
        _listeners = new List<TransportListener>();
        // Before _exposedFeature: the feature exposes the gate's settings.
        _negotiationGate = new NegotiationGate( Logger );
        _exposedFeature = new TransportManagerFeature( this );
        agent.ApplicationIdentityService.AddFeature( _exposedFeature );

        _backTasks = new BackTask<TransportManager>.BackTaskManager( this );
        _headIncomingConnection = BackTask<TransportManager>.Head.Create<IncomingConnectionBackTask>();
        _headOutgoingConnection = BackTask<TransportManager>.Head.Create<OutgoingConnectionBackTask>();
        _headDelayedKillTransport = BackTask<TransportManager>.Head.Create<DelayedKillTransportBackTask>();
        _headKeepAlive = BackTask<TransportManager>.Head.Create<KeepAliveBackTask>();
    }

    /// <summary>
    /// Gets the exposed TransportManager feature.
    /// </summary>
    public TransportManagerFeature Feature => _exposedFeature;

    public ApplicationIdentityService.ISystemClock SystemClock => _agent.SystemClock;

    internal bool Start() => TryStart() == RunningStatus.Running;

    /// <summary>
    /// We cannot use the base SendStop() to stop this agent because
    /// the tear down of the components uses the loop. Instead of introducing
    /// yet another end task in the system, it is easier to use a dedicated stop message.
    /// Let's use this instance as the stop message.
    /// <para>
    /// This is called once all transport features (on Remote) and Listeners (on Locals) have been torn down.
    /// </para>
    /// </summary>
    internal void Stop() => PushTypedJob( this );

    /// <summary>
    /// Gets whether the provided monitor is the one if the <see cref="AppIdentityAgent"/>.
    /// <para>
    /// Remote parties lifetime is handled by the ApplicationIdentity's agent.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to check.</param>
    /// <returns>True if this is the ApplicationIdentity's agent monitor.</returns>
    public bool IsInApplicationIdentityLoop( IActivityMonitor monitor ) => _agent.IsInLoop( monitor );

    /// <summary>
    /// Gets the <see cref="ApplicationIdentityService"/> agent.
    /// </summary>
    public AppIdentityAgent ApplicationIdentityAgent => _agent;

    /// <summary>
    /// Gets the message protocol directory.
    /// </summary>
    public MessageProtocolDirectoryService MessageProtocolDirectory => _protocolDirectory;

    protected override Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount )
    {
        int c = _backTasks.AliveCount;
        if( c > 0 )
        {
            using( monitor.OpenTrace( $"TransportManager heartbeat ({c} active background tasks out of {_backTasks.TotalCount})." ) )
            {
                var (handled, done) = _backTasks.OnHeartBeat( monitor );
                monitor.CloseGroup( $"{done} completed out of {handled} handled." );
            }
        }
        return Task.CompletedTask;
    }

    internal Task RaiseFeatureAppearsEventAsync( IActivityMonitor monitor, TransportFeature t )
    {
        Throw.DebugAssert( IsInApplicationIdentityLoop( monitor ) );
        // When a new feature is created, we immediately raise the Feature.TransportChanged event
        // from the ApplicationIdentity loop but we push a job to update the possible peering issue
        // for the unknown remote (only the full name is none from an incoming message) because
        // the peering issues are managed only from the TransportManager loop.
        PushTypedJob( t );
        return _exposedFeature._transportFeatureChangedEvent.SafeRaiseAsync( monitor, t );
    }

    internal void TryConnectTo( TransportFeature remote )
    {
        PushTypedJob( new TryConnectToJob( remote ) );
    }

    /// <summary>
    /// Gets the admission control for incoming, not yet authenticated, negotiations.
    /// </summary>
    internal NegotiationGate NegotiationGate => _negotiationGate;

    /// <summary>
    /// Called by <see cref="KeepAliveBackTask"/>, whose Check is synchronous while setting the
    /// availability raises an event: this goes back through the loop rather than blocking it.
    /// </summary>
    internal void SignalKeepAliveHealth( TransportFeature feature, bool healthy )
    {
        PushTypedJob( new KeepAliveHealthJob( feature, healthy ) );
    }

    /// <summary>
    /// Called by a listener for a newly accepted connection. Returns false when the connection must
    /// be refused: the listener is then responsible for closing it, and nothing has been queued, so a
    /// flood cannot grow the job queue either.
    /// </summary>
    internal bool IncomingTransport( Transport t, DateTime incomingTime, string? sourceKey )
    {
        if( !_negotiationGate.TryReserve( sourceKey ) ) return false;
        // Reserved here, released by IncomingConnectionBackTask.Reset: the BackTaskManager calls it
        // exactly once per Initialize, on every path including the ones that threw.
        PushTypedJob( new NewIncomingTransport( t, incomingTime, sourceKey ) );
        return true;
    }

    /// <summary>
    /// When called from a Listener (incoming) we have a <paramref name="initialMessage"/> and may be a <paramref name="remote"/>.
    /// When called from an initiator (outgoing), we have a null initialMessage but necessarily a known remote.
    /// </summary>
    /// <param name="initialMessage">Initial message. Never null when listening, always null when calling.</param>
    /// <param name="remote">Locally defined remote. Never null when calling, may be null when listening.</param>
    /// <param name="invalidClockOffset">The invalid clock offset.</param>
    internal void OnInvalidClockOffsetIssue( InitialMessage? initialMessage, TransportFeature? remote, TimeSpan invalidClockOffset )
    {
        Throw.DebugAssert( initialMessage == null || (!initialMessage.IsValidClockOffset && invalidClockOffset == initialMessage.ClockOffset) );
        PushTypedJob( new PeeringIssueJob( PeeringIssueKind.InvalidClockOffset,
                                           initialMessage,
                                           remote,
                                           EnlistUrl: null,
                                           EnlistUrlIsAuthenticated: true,
                                           invalidClockOffset,
                                           RemoteKeyForApproval: null,
                                           LocalMissing: null,
                                           RemoteMissing: null,
                                           RemoteOffMessage: null ) );
    }

    /// <summary>
    /// Listener only.
    /// </summary>
    internal void OnIncomingConfigurationOrTrustIssue( InitialMessage message, TransportFeature? remote, PeeringIssueKind kind, string? enlistUrl )
    {
        Throw.DebugAssert( kind is PeeringIssueKind.IncomingUnknown
                                  or PeeringIssueKind.IncomingDisallowedTransport
                                  or PeeringIssueKind.InvalidClockOffset
                                  or PeeringIssueKind.IncomingUnsupportedTransport
                                  or PeeringIssueKind.InitiatorConflict
                                  or PeeringIssueKind.RequiresLocalApproval
                                  or PeeringIssueKind.RequiresRemoteApproval
                                  or PeeringIssueKind.RequiresBothApproval );
        var usefulRemoteKey = kind is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval
                                ? message.GetCurrentRemoteIdentityKeyData()
                                : null;
        PushTypedJob( new PeeringIssueJob( kind,
                                           message,
                                           remote,
                                           enlistUrl,
                                           // Listener side, and this is NOT our own URL: it is the one the
                                           // remote sent back in its RequiredEnlistUrl reply. That reply is
                                           // only ever requested for RequiresLocal/BothApproval — the cases
                                           // that exist precisely because we do not trust its key yet — so
                                           // its signature verifies against a key it supplied itself.
                                           EnlistUrlIsAuthenticated: false,
                                           InvalidClockOffset: kind is PeeringIssueKind.InvalidClockOffset ? message.ClockOffset : null,
                                           usefulRemoteKey,
                                           LocalMissing: null,
                                           RemoteMissing: null,
                                           RemoteOffMessage: null ) );
    }

    /// <summary>
    /// Initiator only.
    /// </summary>
    /// <param name="enlistUrlIsAuthenticated">
    /// False when <paramref name="enlistUrl"/> came from a reply that did not verify against the key
    /// we already trust for this remote — an unsigned rejection, or one signed by a key we are only
    /// seeing for the first time. Such a URL is a claim by whoever answered the connection, not by
    /// the remote we meant to reach.
    /// </param>
    internal void OnRemoteConfigurationOrTrustIssue( TransportFeature remote,
                                                     PeeringIssueKind kind,
                                                     TimeSpan? clockOffset,
                                                     string? enlistUrl,
                                                     bool enlistUrlIsAuthenticated,
                                                     RemoteIdentityKeyData? remoteKeyForApproval )
    {
        Throw.DebugAssert( remote != null && remote.TargetAddress != null );
        Throw.DebugAssert( kind is PeeringIssueKind.RequiresRemoteCreation
                                or PeeringIssueKind.RemoteDisallowedTransport
                                or PeeringIssueKind.InvalidClockOffset
                                or PeeringIssueKind.RemoteUnsupportedTransport
                                or PeeringIssueKind.InitiatorConflict
                                or PeeringIssueKind.RequiresLocalApproval
                                or PeeringIssueKind.RequiresRemoteApproval
                                or PeeringIssueKind.RequiresBothApproval );
        Throw.DebugAssert( (remoteKeyForApproval != null) == (kind is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval) );
        PushTypedJob( new PeeringIssueJob( kind,
                                           Message: null,
                                           remote,
                                           enlistUrl,
                                           enlistUrlIsAuthenticated,
                                           clockOffset,
                                           remoteKeyForApproval,
                                           LocalMissing: null,
                                           RemoteMissing: null,
                                           RemoteOffMessage: null ) );
    }

    internal void OnRemoteSwitchedOffIssue( TransportFeature remote, GoodbyeMessage offMessage )
    {
        Throw.DebugAssert( remote != null );
        Throw.DebugAssert( "Evicted => Initiator", offMessage.Kind != GoodbyeKind.Evicted || remote.TargetAddress != null );
        PushTypedJob( new PeeringIssueJob( offMessage.Kind == GoodbyeKind.Evicted
                                                ? PeeringIssueKind.RemoteHasBeenEvicted
                                                : PeeringIssueKind.RemoteIsSwitchedOff,
                                           Message: null,
                                           remote,
                                           EnlistUrl: null,
                                           EnlistUrlIsAuthenticated: true,
                                           InvalidClockOffset: null,
                                           RemoteKeyForApproval: null,
                                           LocalMissing: null,
                                           RemoteMissing: null,
                                           RemoteOffMessage: offMessage ) );
    }

    internal void OnRemoteDisallowEvictionIssue( TransportFeature remote )
    {
        Throw.DebugAssert( remote != null && remote.TargetAddress != null );
        PushTypedJob( new PeeringIssueJob( PeeringIssueKind.RemoteDisallowEviction,
                                           Message: null,
                                           remote,
                                           EnlistUrl: null,
                                           EnlistUrlIsAuthenticated: true,
                                           InvalidClockOffset: null,
                                           RemoteKeyForApproval: null,
                                           LocalMissing: null,
                                           RemoteMissing: null,
                                           RemoteOffMessage: null) );
    }

    internal void OnMissingProtocolsIssues( InitialMessage? initialMessage,
                                            TransportFeature remote,
                                            IReadOnlyList<string>? localMissing,
                                            IReadOnlyList<string>? remoteMissing )
    {
        Throw.DebugAssert( remote != null && (localMissing?.Count > 0 || remoteMissing?.Count > 0) );
        PushTypedJob( new PeeringIssueJob( PeeringIssueKind.MissingProtocols,
                                           initialMessage,
                                           remote,
                                           EnlistUrl: null,
                                           EnlistUrlIsAuthenticated: true,
                                           InvalidClockOffset: null,
                                           RemoteKeyForApproval: null,
                                           LocalMissing: localMissing,
                                           RemoteMissing: remoteMissing,
                                           RemoteOffMessage: null ) );
    }

    internal void NewValidTransport( IRemoteParty remote,
                                     Transport transport,
                                     MessageProtocolMap protocolMap,
                                     TimeSpan clockOffset,
                                     GoodbyeMessage.Evicted? evictionMessage )
    {
        Throw.DebugAssert( (evictionMessage != null) == (transport.Listener != null) );
        PushTypedJob( new NewValidTransportJob( remote, transport, protocolMap, clockOffset, evictionMessage ) );
    }

    internal void DelayedKillTransport( Transport transport, int outgoingReconnectDelay )
    {
        if( !transport.Lifetime.IsCancellationRequested )
        {
            PushTypedJob( new KillTransportJob( transport, outgoingReconnectDelay, Delayed: true ) );
        }
    }

    /// <summary>
    /// Handled by <see cref="KillTransportAsync"/>.
    /// </summary>
    /// <param name="transport">Can be a in or outgoing.</param>
    /// <param name="outgoingReconnectDelay">
    /// Applies only to outgoing: <see cref="int.MaxValue"/> to stop retrying, 0 to retry asap.
    /// </param>
    internal void KillTransport( Transport transport, int outgoingReconnectDelay )
    {
        if( transport.OnKilled() )
        {
            PushTypedJob( new KillTransportJob( transport, outgoingReconnectDelay, Delayed: false ) );
        }
    }

    internal void SwitchOff( TransportFeature feature, GoodbyeMessage reason )
    {
        PushTypedJob( new SwitchOffJob( feature, null, reason ) );
    }

    internal void SwitchOn( TransportFeature feature )
    {
        PushTypedJob( new SwitchOnJob( feature ) );
    }

    internal Task TearDownAsync( TransportFeature feature, bool serviceShutdown )
    {
        GoodbyeMessage reason = serviceShutdown
                                    ? new GoodbyeMessage.ApplicationIdentityShutdown( false )
                                    : new GoodbyeMessage.PartyDestroyed( false );
        feature.SetTornDownSwitchOff( reason );
        var tcs = new TaskCompletionSource( TaskCreationOptions.RunContinuationsAsynchronously );
        PushTypedJob( new SwitchOffJob( feature, tcs, reason ) );
        return tcs.Task;
    }

    // A new TransportFeature is directly the TransportFeature object.
    sealed record class PeeringIssueJob( PeeringIssueKind Kind,
                                         InitialMessage? Message,
                                         TransportFeature? Remote,
                                         string? EnlistUrl,
                                         // Deliberately positional next to EnlistUrl and without a default:
                                         // a URL an operator is invited to act on must never reach the issue
                                         // pipeline without its provenance travelling with it.
                                         bool EnlistUrlIsAuthenticated,
                                         TimeSpan? InvalidClockOffset,
                                         RemoteIdentityKeyData? RemoteKeyForApproval,
                                         IReadOnlyList<string>? LocalMissing,
                                         IReadOnlyList<string>? RemoteMissing,
                                         GoodbyeMessage? RemoteOffMessage );
    sealed record class TryConnectToJob( TransportFeature Remote );
    sealed record class NewIncomingTransport( Transport Incoming, DateTime IncomingTime, string? SourceKey );
    sealed record class NewValidTransportJob( IRemoteParty Remote, Transport Transport, MessageProtocolMap Protocols, TimeSpan ClockOffset, GoodbyeMessage.Evicted? EvictionMessage );
    sealed record class KillTransportJob( Transport Transport, int ReconnectDelay, bool Delayed );
    sealed record class SwitchOffJob( TransportFeature Feature, TaskCompletionSource? Done, GoodbyeMessage Reason );
    sealed record class SwitchOnJob( TransportFeature Feature );
    sealed record class KeepAliveHealthJob( TransportFeature Feature, bool Healthy );

    protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
    {
        switch( job )
        {
            case KillTransportJob j:
                if( j.Delayed )
                {
                    if( !j.Transport.Lifetime.IsCancellationRequested )
                    {
                        _backTasks.Initialize<DelayedKillTransportBackTask>( monitor, _headDelayedKillTransport, back => back.OnInitialize( j.Transport, j.ReconnectDelay ) );
                    }
                    return default;
                }
                return KillTransportAsync( monitor, j.Transport, j.ReconnectDelay );
            case TryConnectToJob c:
                var f = c.Remote;
                Throw.DebugAssert( f.TargetAddress != null );
                monitor.Trace( $"Initiating connection to '{f.TargetAddress}' for '{f.Party.FullName}' immediately." );
                _backTasks.Initialize<OutgoingConnectionBackTask>( monitor, _headOutgoingConnection, back => back.OnInitialize( f, 0 ) );
                return default;
            case NewIncomingTransport j:
                Throw.DebugAssert( "This is necessarily an incoming connection created by a listener (not yet validated).",
                                   j.Incoming.Listener != null && j.Incoming.Controller == null );
                monitor.Trace( $"Received transport '{j.Incoming.RemoteEndPointDescription}' (#{j.Incoming.GetHashCode()}) from '{j.Incoming.Listener}'. Validating it." );
                _backTasks.Initialize<IncomingConnectionBackTask>( monitor, _headIncomingConnection, back => back.OnInitialize( j.Incoming, j.IncomingTime, j.SourceKey ) );
                return default;
            case TransportFeature newFeature:
                return HandleNewRemoteTransportFeatureAsync( monitor, newFeature );
            case PeeringIssueJob p:
                return HandlePeeringIssueAsync( monitor, p );
            case NewValidTransportJob j:
                return HandleNewValidTransportAsync( monitor, j, _exposedFeature );
            case KeepAliveHealthJob k:
                return new ValueTask( k.Feature.SetKeepAliveHealthAsync( monitor, k.Healthy ) );
            case SwitchOnJob on:
                return on.Feature.DoSwitchOnAsync( monitor );
            case SwitchOffJob off:
                return off.Feature.DoSwitchOffAsync( monitor, off.Done, off.Reason );
        }
        if( job == this )
        {
            _backTasks.Destroy( monitor );
            // Sends the MicroAgent stop marker.
            SendStop();
            return default;
        }
        return base.ExecuteTypedJobAsync( monitor, job );
    }

    async ValueTask HandleNewRemoteTransportFeatureAsync( IActivityMonitor monitor, TransportFeature newFeature )
    {
        await _exposedFeature.OnRemoteAppearedAsync( monitor, newFeature );
    }

    async ValueTask KillTransportAsync( IActivityMonitor monitor, Transport t, int reconnectDelay )
    {
        // Starts by disposing the current transport before attempting to reconnect.
        try
        {
            await t.DestroyAsync( monitor );
        }
        catch( Exception ex )
        {
            monitor.Error( $"While destroying transport '{t.GetType():C} - {t.RemoteEndPointDescription}'.", ex );
        }
        // If the transport is an outgoing connection and has been activated, launch the
        // reconnection back task.
        if( t.Controller != null )
        {
            monitor.Trace( $"Killed validated transport '{t.RemoteEndPointDescription}' (#{t.GetHashCode()})." );
            if( t.TargetAddress != null )
            {
                var remote = t.Controller.Feature;
                if( !remote.IsOff && reconnectDelay != int.MaxValue )
                {
                    // This transport was negotiated and then died. Fold it into the remote's flap
                    // count and never retry sooner than that allows. Callers say 0 for "asap", and
                    // obeying them literally turns one bad frame from a peer into a tight
                    // connect/negotiate/kill loop. An explicitly longer delay (a Goodbye can ask for
                    // one) is still honoured.
                    var backOff = remote.NextReconnectDelay( SystemClock.UtcNow );
                    if( reconnectDelay < backOff ) reconnectDelay = backOff;
                    if( remote.FlapCount > 1 )
                    {
                        monitor.Warn( $"Remote '{remote.Party.FullName}' has dropped us {remote.FlapCount} times in a row without staying connected." );
                    }
                    // Wording kept verbatim: TcpTransportTests asserts on this exact line, and a delay
                    // is indeed a second when the heartbeat runs at its default 1000 ms.
                    monitor.Trace( $"Initiating reconnection attempt to '{remote.TargetAddress}' for '{remote.Party.FullName}' in {reconnectDelay} seconds." );
                    // We are connecting. The ConnectionAvailability should be Connected (but may already be Low or even DangerZone).
                    // The ConnectionAvailability should be set to Low if it was Connected.
                    await remote.SetMaxConnectionAvailabilityAsync( monitor, ConnectionAvailability.Low );
                    _backTasks.Initialize<OutgoingConnectionBackTask>( monitor, _headOutgoingConnection, back => back.OnInitialize( remote, reconnectDelay ) );
                }
            }
        }
    }

    async ValueTask HandlePeeringIssueAsync( IActivityMonitor monitor, PeeringIssueJob job )
    {
        await _exposedFeature.AddOrUpdateIssueAsync( monitor,
                                                     job.Kind,
                                                     job.Message,
                                                     job.Remote,
                                                     job.EnlistUrl,
                                                     job.EnlistUrlIsAuthenticated,
                                                     job.InvalidClockOffset,
                                                     job.RemoteKeyForApproval,
                                                     job.LocalMissing,
                                                     job.RemoteMissing,
                                                     job.RemoteOffMessage );
    }

    async ValueTask HandleNewValidTransportAsync( IActivityMonitor monitor,
                                                  NewValidTransportJob job,
                                                  TransportManagerFeature forPeeringIssue )
    {
        Transport t = job.Transport;
        using( monitor.OpenInfo( $"New valid {(t.Listener != null ? "incoming" : "outgoing")} transport '{t}' (#{t.GetHashCode()}) for '{job.Remote}'." ) )
        {
            // Handle a potential race condition: the Party may be destroyed or switched off.
            // In such case, the new valid transport must be destroyed but before we should send
            // the appropriate Goodbye message.
            var remote = job.Remote;
            var feature = remote.IsDestroyed ? null : remote.GetFeature<TransportFeature>();
            var offMessage = feature?.SwitchOffMessage;
            if( feature != null && offMessage == null )
            {
                await forPeeringIssue.OnTransportAvailableAsync( monitor, feature );
                await feature.OnTransportAppearAsync( monitor, t, job.Protocols, job.ClockOffset, job.EvictionMessage );
                // The transport has a controller from here, so it can send. One watcher per live
                // transport: it ends itself when the transport is condemned and goes back to the pool.
                _backTasks.Initialize<KeepAliveBackTask>( monitor, _headKeepAlive, back => back.OnInitialize( t ) );
            }
            else
            {
                // This transport has not yet been handled by a TransportController: there are
                // no receive nor send loop: we can use it to send the offMessage if there's one
                // and if it doesn't come from the remote.
                if( offMessage != null )
                {
                    monitor.Info( $"Remote '{remote.FullName}' is off: {offMessage}" );
                    if( !offMessage.IsFromRemote )
                    {
                        monitor.Info( "Sending Goodbye message and destroying the new valid transport in 1 second." );
                        DelayedKillTransport( t, int.MaxValue );
                        await ZeroProtocol.SendGoodbyeMessageAsync( t, offMessage );
                        return;
                    }
                }
                monitor.Info( "Destroying the new valid transport." );
                KillTransport( t, int.MaxValue );
            }
        }
    }

}
