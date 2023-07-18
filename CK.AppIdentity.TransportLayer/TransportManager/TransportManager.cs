using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.PerfectEvent;
using Microsoft.VisualBasic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

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
        readonly AppIdentityAgent _agent;
        readonly MessageProtocolDirectoryService _protocolDirectory;
        readonly List<TransportListener> _listeners;
        readonly TransportManagerFeature _exposedFeature;

        // Heart beats handles the BackTask list.
        readonly Timer _heartbeat;
        readonly BackTask.List _backTasks;
        readonly BackTask.Head _headIncomingConnection;
        readonly BackTask.Head _headOutgoingConnection;
        bool _inHeartBeat;
        int _heartBeatReentrantCount;

        readonly List<InitialMessage> _waitingList;
        readonly PerfectEventSender<InitialMessage> _waitingListChanged;

        internal TransportManager( AppIdentityAgent agent, MessageProtocolDirectoryService protocolDirectory )
            : base( $"TransportManager for {agent.ApplicationIdentityService}" )
        {
            _agent = agent;
            _protocolDirectory = protocolDirectory;
            _listeners = new List<TransportListener>();
            _exposedFeature = new TransportManagerFeature();
            agent.ApplicationIdentityService.AddFeature( _exposedFeature );

            _backTasks = new BackTask.List( this );
            _headIncomingConnection = BackTask.Head.Create<IncomingConnectionBackTask>();
            _headOutgoingConnection = BackTask.Head.Create<OutgoingConnectionBackTask>();
            _heartbeat = new Timer( OnTimer, this, 1000, 1000 );

            _waitingList = new List<InitialMessage>();
            _waitingListChanged = new PerfectEventSender<InitialMessage>();
        }

        public TransportManagerFeature Feature => _exposedFeature;

        static void OnTimer( object? state ) => Unsafe.As<TransportManager>( state! ).PushTypedJob( DBNull.Value );

        internal bool Start() => TryStart() == RunningStatus.Running;

        /// <summary>
        /// We cannot use the base SendStop() to stop this agent because
        /// the tear down of the components uses the loop. Instead of introducing
        /// yet another end task in the system, it is easier to use a dedicated stop message.
        /// Let's use this instance as the stop message.
        /// <para>
        /// This is called once all TransportFeature have been torn down.
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

        internal Task RaiseFeatureAppearsEventAsync( IActivityMonitor monitor, TransportFeature t )
        {
            Debug.Assert( IsInApplicationIdentityLoop( monitor ) );
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

        internal void UnknownIncomingRemote( InitialMessage m, RemoteIdentityKey? trustedIdentity )
        {
            PushTypedJob( new UnknownIncomingRemoteJob( m, trustedIdentity ) );
        }

        internal void NewValidTransport( IRemoteParty remote, Transport transport, MessageProtocolMap protocolMap, TimeSpan clockDrift )
        {
            PushTypedJob( new NewValidTransportJob( remote, transport, protocolMap, clockDrift ) );
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
            PushTypedJob( new SwitchOffJob( feature, reason ) );
        }

        internal void SwitchOn( TransportFeature feature )
        {
            PushTypedJob( feature );
        }

        internal void TearDown( TransportFeature feature )
        {
            // The empty string is the "Torn down" marker:
            // it is unconditionally set here so that no more transition to "on" is possible.
            feature.SetTornDownSwitchOff();
            PushTypedJob( new SwitchOffJob( feature, string.Empty ) );
        }

        sealed record class UnknownIncomingRemoteJob( InitialMessage Message, RemoteIdentityKey? TrustedIdentity );
        // A new incoming Transport from a TransportListener is directly the Transport object.
        // The heart beat (timer) is DBNull.Value instance.
        // SwitchOn of a TransportFeature is the transport feature itself.
        sealed record class TryConnectToJob( TransportFeature Remote );
        sealed record class NewValidTransportJob( IRemoteParty Remote, Transport Transport, MessageProtocolMap Protocols, TimeSpan clockDrift );
        sealed record class KillTransportJob( Transport Transport, TimeSpan ShutUp );
        sealed record class SwitchOffJob( TransportFeature Feature, string Reason );

        protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case DBNull: // Heartbeat.
                    {
                        // This is mainly when debugging. In practice, no back tasks check
                        // should be longer than 1 second.
                        if( _inHeartBeat )
                        {
                            ++_heartBeatReentrantCount;
                            if( !Debugger.IsAttached )
                            {
                                monitor.Warn( $"Heartbeat blocked for {_heartBeatReentrantCount} count." );
                            }
                        }
                        else
                        {
                            _heartBeatReentrantCount = 0;
                            _inHeartBeat = true;
                            int c = _backTasks.AliveCount;
                            if( c > 0 )
                            {
                                using( monitor.OpenTrace( $"TransportManager heartbeat ({c} active background tasks out of {_backTasks.TotalCount})." ) )
                                {
                                    var (handled, done) = _backTasks.OnHeartBeat( monitor );
                                    monitor.CloseGroup( $"{done} completed out of {handled} handled." );
                                }
                            }
                            _inHeartBeat = false;
                        }
                        return default;
                    }
                case KillTransportJob j:
                    return HandleKillTransport( monitor, j );
                case TryConnectToJob c:
                    var f = c.Remote;
                    Debug.Assert( f.TargetAddress != null );
                    monitor.Trace( $"Initiating connection to '{f.TargetAddress}' for '{f.Party.FullName}' immediately." );
                    _backTasks.Initialize<OutgoingConnectionBackTask>( _headOutgoingConnection, back => back.Setup( this, f ), 1 );
                    return default;
                case Transport t:
                    Debug.Assert( t.Listener != null, "This is necessarily an incoming connection created by a listener." );
                    monitor.Trace( $"Received transport '{t.RemoteEndPointDescription}' (#{t.GetHashCode()}) from listener '{t.Listener.EndPointDescription}'. Validating it." );
                    _backTasks.Initialize<IncomingConnectionBackTask>( _headIncomingConnection, back => back.Setup( this, t ), 2 );
                    return default;
                case UnknownIncomingRemoteJob m:
                    return HandleUnknownIncomingRemote( monitor, m );
                case NewValidTransportJob j:
                    return HandleNewValidTransport( monitor, j );
                case TransportFeature switchOn:
                    return switchOn.DoSwitchOnAsync( monitor );
                case SwitchOffJob off:
                    return off.Feature.DoSwitchOffAsync( monitor, off.Reason );
            }
            if( job == this )
            {
                return HandleStopAsync( monitor );
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        async ValueTask HandleStopAsync( IActivityMonitor monitor )
        {
            _heartbeat.Dispose();
            _backTasks.Destroy( monitor );
            await DisposeListenersAsync( monitor );
            // Sends the MicroAgent stop marker.
            SendStop();
        }

        async ValueTask HandleKillTransport( IActivityMonitor monitor, KillTransportJob j )
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
                        var f = t.Controller.Feature;
                        if( !f.IsOff )
                        {
                            var seconds = (int)Math.Floor( j.ShutUp.TotalSeconds );
                            monitor.Trace( $"Initiating reconnection attempt to '{f.TargetAddress}' for '{f.Party.FullName}' in {seconds} seconds." );
                            _backTasks.Initialize<OutgoingConnectionBackTask>( _headOutgoingConnection, back => back.Setup( this, f ), seconds + 1 );
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

        async ValueTask HandleUnknownIncomingRemote( IActivityMonitor monitor, UnknownIncomingRemoteJob job )
        {
            _waitingList.Add( job.Message );
            await _waitingListChanged.SafeRaiseAsync( monitor, job.Message );
        }

        static async ValueTask HandleNewValidTransport( IActivityMonitor monitor, NewValidTransportJob remoteTransport )
        {
            Transport t = remoteTransport.Transport;
            using( monitor.OpenInfo( $"New valid {(t.Listener != null ? "incoming" : "outgoing")} transport '{t}' (#{t.GetHashCode()}) for '{remoteTransport.Remote.FullName}'." ) )
            {
                var remote = remoteTransport.Remote;
                var feature = remote.IsDestroyed ? null : remote.GetFeature<TransportFeature>();
                if( feature != null && !feature.IsOff )
                {
                    await feature.OnTransportAppearAsync( monitor, t, remoteTransport.Protocols );
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
