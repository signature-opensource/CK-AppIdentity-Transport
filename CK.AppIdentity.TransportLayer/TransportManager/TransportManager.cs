using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.PerfectEvent;
using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// <see cref="MicroAgent"/> that manages the <see cref="Transport"/> remote's features.
    /// <para>
    /// This class is internal but exposes the public <see cref="TransportManagerFeature"/>.
    /// </para>
    /// </summary>
    sealed partial class TransportManager : MicroAgent
    {
        /// <summary>
        /// Maximal time allowed for a connection to be negotiated.
        /// This delay is not based on the heartbeat count.
        /// </summary>
        public const int NegotiationTimeout = 2000;

        readonly AppIdentityAgent _agent;
        readonly MessageProtocolDirectoryService _protocolDirectory;
        readonly List<TransportListener> _listeners;
        readonly TransportManagerFeature _exposedFeature;

        // ApplicationIdentityService's heart beat handles the BackTask list.
        readonly BackTask.List _backTasks;
        readonly BackTask.Head _headIncomingConnection;
        readonly BackTask.Head _headOutgoingConnection;

        internal TransportManager( AppIdentityAgent agent, MessageProtocolDirectoryService protocolDirectory )
            : base( $"TransportManager for {agent.ApplicationIdentityService}", agent.SystemClock.HeatBeatPeriod )
        {
            _agent = agent;
            _protocolDirectory = protocolDirectory;
            _listeners = new List<TransportListener>();
            _exposedFeature = new TransportManagerFeature( this );
            agent.ApplicationIdentityService.AddFeature( _exposedFeature );

            _backTasks = new BackTask.List( this );
            _headIncomingConnection = BackTask.Head.Create<IncomingConnectionBackTask>();
            _headOutgoingConnection = BackTask.Head.Create<OutgoingConnectionBackTask>();
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
            // for the unknwon remote (only the full name is none from an incoming message) because
            // the peering issues are managed only from the TransportManager loop.
            PushTypedJob( t );
            return _exposedFeature._transportFeatureChangedEvent.SafeRaiseAsync( monitor, t );
        }

        internal void TryConnectTo( TransportFeature remote )
        {
            PushTypedJob( new TryConnectToJob( remote ) );
        }

        internal void IncomingTransport( Transport t )
        {
            PushTypedJob( t );
        }

        /// <summary>
        /// When called from a Listener (incoming) we have a <paramref name="initialMessage"/> and may be a <paramref name="remote"/>.
        /// When called from an initiator (outgoing), we have a null initialMessage but necessarily a known remote.
        /// </summary>
        /// <param name="initialMessage">Initial message. Never null when listening, always null when calling.</param>
        /// <param name="remote">Locally defined remote. Never null when calling, may be null when listening.</param>
        /// <param name="invalidClockOffset">The invalid clock offset.</param>
        internal void InvalidClockOffset( InitialMessage? initialMessage, TransportFeature? remote, TimeSpan invalidClockOffset )
        {
            Throw.DebugAssert( initialMessage == null || (!initialMessage.ValidClockOffset && invalidClockOffset == initialMessage.ClockOffset) );
            PushTypedJob( new PeeringIssueJob( PeeringIssueKind.InvalidClockOffset, initialMessage, remote, null, invalidClockOffset ) );
        }

        /// <summary>
        /// Listener only. The remote may be known or not (it is then untrusted) or it's an initiator conflict
        /// or our remote transport feature is disabled or the TransportListener is not the right one.
        /// </summary>
        /// <param name="m">The initial message received.</param>
        /// <param name="remote">The remote if knwon.</param>
        internal void UnknownOrUntrustedIncomingRemote( InitialMessage m, TransportFeature? remote, PeeringIssueKind kind )
        {
            Throw.DebugAssert( kind == PeeringIssueKind.UnknwonIncoming
                          || kind == PeeringIssueKind.UntrustedIncoming
                          || kind == PeeringIssueKind.UnsupportedTransportIncoming
                          || kind == PeeringIssueKind.DisallowedTransportIncoming
                          || kind == PeeringIssueKind.InitiatorConflict );
            PushTypedJob( new PeeringIssueJob( kind, m, remote, null, null ) );
        }

        /// <summary>
        /// Initiator only.
        /// </summary>
        /// <param name="remote">The calling remote.</param>
        /// <param name="enlistUrl">
        /// The remote enlist url if provided. Can be "!DisallowedTransportIncoming", "!InitiatorConflict" or "!UnsupportedTransportIncoming".
        /// </param>
        /// <param name="created">True if we exist in the remote system but are not yet trusted.</param>
        internal void TargetRequiresCreationOrApproval( TransportFeature remote, string? enlistUrl, bool created )
        {

            PeeringIssueKind kind;
            switch( enlistUrl )
            {
                case ZeroProtocol.EnlistUrlDisallowedTransport:
                    kind = PeeringIssueKind.RemoteDisallowedTransport;
                    enlistUrl = null;
                    break;
                case ZeroProtocol.EnlistUrlInitiatorConflict:
                    kind = PeeringIssueKind.InitiatorConflict;
                    enlistUrl = null;
                    break;
                case ZeroProtocol.EnlistUrlUnsupportedTransport:
                    kind = PeeringIssueKind.RemoteUnsupportedTransport;
                    enlistUrl = null;
                    break;
                default:
                    kind = created ? PeeringIssueKind.WaitingRemoteApproval : PeeringIssueKind.WaitingRemoteCreation;
                    break;
            };
            PushTypedJob( new PeeringIssueJob( kind, null, remote, enlistUrl, null ) );
        }

        internal void NewValidTransport( IRemoteParty remote, Transport transport, MessageProtocolMap protocolMap, TimeSpan clockOffset )
        {
            PushTypedJob( new NewValidTransportJob( remote, transport, protocolMap, clockOffset ) );
        }

        internal void KillTransport( Transport transport )
        {
            PushTypedJob( new KillTransportJob( transport, TimeSpan.Zero ) );
        }

        internal void KillTransport( Transport transport, TimeSpan shutUp )
        {
            PushTypedJob( new KillTransportJob( transport, shutUp ) );
        }

        internal void SwitchOff( TransportFeature feature, string reason )
        {
            PushTypedJob( new SwitchOffJob( feature, null, reason ) );
        }

        internal void SwitchOn( TransportFeature feature )
        {
            PushTypedJob( new SwitchOnJob( feature ) );
        }

        internal Task TearDownAsync( TransportFeature feature )
        {
            // The empty string is the "Torn down" marker:
            // it is unconditionally set here so that no more transition to "on" is possible.
            feature.SetTornDownSwitchOff();
            var tcs = new TaskCompletionSource( TaskCreationOptions.RunContinuationsAsynchronously );
            PushTypedJob( new SwitchOffJob( feature, tcs, string.Empty ) );
            return tcs.Task;
        }

        // A new incoming Transport from a TransportListener is directly the Transport object.
        // A new TransportFeature is directly the TransportFeature object.
        // The heart beat (timer) is DBNull.Value instance.
        sealed record class PeeringIssueJob( PeeringIssueKind Kind, InitialMessage? Message, TransportFeature? Remote, string? EnlistUrl, TimeSpan? InvalidClockOffset );
        sealed record class TryConnectToJob( TransportFeature Remote );
        sealed record class NewValidTransportJob( IRemoteParty Remote, Transport Transport, MessageProtocolMap Protocols, TimeSpan ClockOffset );
        sealed record class KillTransportJob( Transport Transport, TimeSpan ShutUp );
        sealed record class SwitchOffJob( TransportFeature Feature, TaskCompletionSource? Done, string Reason );
        sealed record class SwitchOnJob( TransportFeature Feature );

        protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case KillTransportJob j:
                    return HandleKillTransportAsync( monitor, j );
                case TryConnectToJob c:
                    var f = c.Remote;
                    Throw.DebugAssert( f.TargetAddress != null );
                    monitor.Trace( $"Initiating connection to '{f.TargetAddress}' for '{f.Party.FullName}' immediately." );
                    _backTasks.Initialize<OutgoingConnectionBackTask>( monitor, _headOutgoingConnection, back => back.OnInitialize( this, f, 0 ) );
                    return default;
                case Transport t:
                    Throw.DebugAssert( t.Listener != null, "This is necessarily an incoming connection created by a listener." );
                    monitor.Trace( $"Received transport '{t.RemoteEndPointDescription}' (#{t.GetHashCode()}) from listener '{t.Listener.EndPointDescription}'. Validating it." );
                    _backTasks.Initialize<IncomingConnectionBackTask>( monitor, _headIncomingConnection, back => back.OnInitialize( this, t ) );
                    return default;
                case TransportFeature newFeature:
                    return HandleNewRemoteTransportFeatureAsync( monitor, newFeature );
                case PeeringIssueJob p:
                    return HandlePeeringIssueAsync( monitor, p );
                case NewValidTransportJob j:
                    return HandleNewValidTransportAsync( monitor, j, _exposedFeature );
                case SwitchOnJob on:
                    return on.Feature.DoSwitchOnAsync( monitor );
                case SwitchOffJob off:
                    return off.Feature.DoSwitchOffAsync( monitor, off.Done, off.Reason );
            }
            if( job == this )
            {
                return HandleStopAsync( monitor );
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        ValueTask HandleStopAsync( IActivityMonitor monitor )
        {
            _backTasks.Destroy( monitor );
            // Sends the MicroAgent stop marker.
            SendStop();
            return default;
        }

        async ValueTask HandleNewRemoteTransportFeatureAsync( IActivityMonitor monitor, TransportFeature newFeature )
        {
            await _exposedFeature.OnRemoteAppearedAsync( monitor, newFeature );
        }

        async ValueTask HandleKillTransportAsync( IActivityMonitor monitor, KillTransportJob j )
        {
            var t = j.Transport;
            if( t.SetHardCondemned() )
            {
                // Starts by disposing the current transport before attempting to reconnect.
                await SafeDestroyTransportAsync( monitor, t );
                // If the transport is an outgoing connection and has been activated, launch the
                // reconnection back task.
                if( t.Controller != null )
                {
                    monitor.Trace( $"Killing validated transport '{t.RemoteEndPointDescription}' (#{t.GetHashCode()})." );
                    if( t.TargetAddress != null )
                    {
                        var remote = t.Controller.Feature;
                        if( !remote.IsOff )
                        {
                            var seconds = (int)Math.Ceiling( j.ShutUp.TotalSeconds );
                            monitor.Trace( $"Initiating reconnection attempt to '{remote.TargetAddress}' for '{remote.Party.FullName}' in {seconds} seconds." );
                            _backTasks.Initialize<OutgoingConnectionBackTask>( monitor, _headOutgoingConnection, back => back.OnInitialize( this, remote, seconds ) );
                        }
                    }
                }
            }
        }

        static async ValueTask SafeDestroyTransportAsync( IActivityMonitor monitor, Transport t )
        {
            try
            {
                await t.DestroyAsync( monitor );
            }
            catch( Exception ex )
            {
                monitor.Error( $"While destroying transport '{t.GetType():C} - {t.RemoteEndPointDescription}'.", ex );
            }
        }

        async ValueTask HandlePeeringIssueAsync( IActivityMonitor monitor, PeeringIssueJob job )
        {
            await _exposedFeature.AddOrUpdateIssueAsync( monitor, job.Kind, job.Message, job.Remote, job.EnlistUrl, job.InvalidClockOffset );
        }

        static async ValueTask HandleNewValidTransportAsync( IActivityMonitor monitor, NewValidTransportJob remoteTransport, TransportManagerFeature forPeeringIssue )
        {
            Transport t = remoteTransport.Transport;
            using( monitor.OpenInfo( $"New valid {(t.Listener != null ? "incoming" : "outgoing")} transport '{t}' (#{t.GetHashCode()}) for '{remoteTransport.Remote}'." ) )
            {
                var remote = remoteTransport.Remote;
                var feature = remote.IsDestroyed ? null : remote.GetFeature<TransportFeature>();
                if( feature != null && !feature.IsOff )
                {
                    await forPeeringIssue.OnTransportAvailableAsync( monitor, feature );
                    await feature.OnTransportAppearAsync( monitor, t, remoteTransport.Protocols, remoteTransport.ClockOffset );
                }
                else
                {
                    if( remote.IsDestroyed )
                    {
                        monitor.Info( $"Remote '{remote.FullName}' has been destroyed." );
                    }
                    else if( feature != null && feature.IsOff )
                    {
                        monitor.Info( $"Transport feature for '{remote.FullName}' is off line." );
                    }
                    else
                    {
                        monitor.Error( $"Transport feature has been removed from '{remote.FullName}' party." );
                    }
                    monitor.Info( "Destroying the new valid transport." );
                    t.SetHardCondemned();
                    await SafeDestroyTransportAsync( monitor, t );
                }
            }
        }

    }
}
