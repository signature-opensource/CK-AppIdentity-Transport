using CK.Core;
using CK.PerfectEvent;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.TransportLayer
{

    public interface ITransportManager
    {
        /// <summary>
        /// Gets the <see cref="ApplicationIdentityService"/> agent.
        /// </summary>
        AppIdentityAgent ApplicationIdentityAgent { get; }

    }

    public sealed partial class TransportManager : MicroAgent
    {
        readonly AppIdentityAgent _agent;
        readonly MessageProtocolDirectoryService _protocolDirectory;

        // Heart beats handles the BackTask list.
        readonly Timer _heartbeat;
        readonly BackTask.List _backTasks;
        readonly BackTask.Head _headIncomingConnection;
        readonly BackTask.Head _headOutgoingConnection;

        readonly List<InitialMessage> _waitingList;
        readonly PerfectEventSender<InitialMessage> _waitingListChanged;

        internal TransportManager( AppIdentityAgent agent, MessageProtocolDirectoryService protocolDirectory )
            : base( $"TransportManager for '{agent.ApplicationIdentityService}'." )
        {
            _agent = agent;
            _protocolDirectory = protocolDirectory;
            _waitingList = new List<InitialMessage>();
            _waitingListChanged = new PerfectEventSender<InitialMessage>();
            _backTasks = new BackTask.List( this );
            _headIncomingConnection = BackTask.Head.Create<IncomingConnectionBackTask>();
            _headOutgoingConnection = BackTask.Head.Create<OutgoingConnectionBackTask>();
            _heartbeat = new Timer( OnTimer, this, 1000, 1000 );

        }

        static void OnTimer( object? state ) => Unsafe.As<TransportManager>( state! ).PushTypedJob( DBNull.Value );

        internal bool Start() => TryStart() == RunningStatus.Running;

        internal new void SendStop() => base.SendStop();

        protected override ValueTask OnStopAsync( IActivityMonitor monitor )
        {
            _heartbeat.Dispose();
            _backTasks.Destroy( monitor );
            return base.OnStopAsync( monitor );
        }

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

        internal void TryConnectTo( TransportFeature remote, TransportTypeAddress target )
        {
            PushTypedJob( new TryConnectToJob( remote, target ) );
        }

        internal void IncomingTransport( Transport t )
        {
            PushTypedJob( t );
        }

        internal void UnknownIncomingRemote( InitialMessage m )
        {
            PushTypedJob( m );
        }

        internal void NewValidTransport( IRemoteParty remote, Transport transport, MessageProtocolMap protocolMap )
        {
            PushTypedJob( new NewValidTransportJob( remote, transport, protocolMap ) );
        }

        internal void TransportErrorSendMessage( Transport transport, Exception ex )
        {
            PushTypedJob( new CondemnTransportJob( transport, ex ) );
        }

        internal void CondemnTransport( Transport transport )
        {
            PushTypedJob( new CondemnTransportJob( transport, null ) );
        }

        // A new incoming Transport from a TransportListener is directly the Transport object.
        // An unknown incoming connection is directly the InitialMessage.
        sealed record class TryConnectToJob( TransportFeature Remote, TransportTypeAddress Target );
        sealed record class NewValidTransportJob( IRemoteParty Remote, Transport Transport, MessageProtocolMap Protocols );
        sealed record class CondemnTransportJob( Transport Transport, Exception? Exception );

        protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case DBNull:
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
                        return default;
                    }
                case TryConnectToJob c:
                    monitor.Trace( $"Initiating connection to '{c.Target}' for '{c.Remote.Party.FullName}'." );
                    _backTasks.Initialize<OutgoingConnectionBackTask>( _headOutgoingConnection, back => back.Setup( this, c.Remote, c.Target ), 1 );
                    return default;
                case Transport t:
                    Debug.Assert( t.Listener != null, "This is necessarily an incoming connection created by a listener." );
                    monitor.Trace( $"Received connection '{t.RemoteEndPointDescription}' from listener '{t.Listener.EndPointDescription}'." );
                    _backTasks.Initialize<IncomingConnectionBackTask>( _headIncomingConnection, back => back.Setup( this, t ), 2 );
                    return default;
                case InitialMessage m:
                    return HandleUnknownIncomingRemote( monitor, m );
                case NewValidTransportJob j:
                    return HandleNewValidTransport( monitor, j );
                case CondemnTransportJob j:
                    return HandleCondemnTransport( monitor, j );
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        async ValueTask HandleCondemnTransport( IActivityMonitor monitor, CondemnTransportJob j )
        {
            var t = j.Transport;
            using( monitor.OpenGroup( j.Exception != null ? LogLevel.Error : LogLevel.Trace, $"Condemning transport '{t}'.", j.Exception ) )
            {
                t.SetCondemned( monitor );
                // Starts by disposing the current transport before attempting to reconnect.
                await SafeDestroyTransportAsync( monitor, t );
                // If the transport is an outgoing connection and has been activated, launch the
                // reconnection back task.
                if( t.TargetAddress != null && t.Controller != null && !t.Controller.Feature.Party.IsDestroyed )
                {
                    var f = t.Controller.Feature;
                    if( !f.Party.IsDestroyed )
                    {
                        monitor.Trace( $"Initiating reconnection attempt to '{t.TargetAddress}' for '{f.Party.FullName}'." );
                        _backTasks.Initialize<OutgoingConnectionBackTask>( _headOutgoingConnection, back => back.Setup( this, f, t.TargetAddress ), 1 );
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

        async ValueTask HandleUnknownIncomingRemote( IActivityMonitor monitor, InitialMessage initialMessage )
        {
            _waitingList.Add( initialMessage );
            await _waitingListChanged.SafeRaiseAsync( monitor, initialMessage );
        }

        static async ValueTask HandleNewValidTransport( IActivityMonitor monitor, NewValidTransportJob remoteTransport )
        {
            using( monitor.OpenInfo( $"New transport '{remoteTransport.Transport}' for '{remoteTransport.Remote.FullName}'." ) )
            {
                IRemoteParty remote = remoteTransport.Remote;
                var feature = remote.IsDestroyed ? null : remote.GetFeature<TransportFeature>();
                if( feature != null )
                {
                    await feature.OnTransportAppearAsync( monitor, remoteTransport.Transport, remoteTransport.Protocols );
                }
                else
                {
                    remoteTransport.Transport.SetCondemned( monitor );
                    if( remote.IsDestroyed )
                    {
                        monitor.Info( $"Remote '{remote.FullName}' has been destroyed. Destroying the new transport." );
                    }
                    else
                    {
                        monitor.Error( $"Transport feature has been removed from '{remote.FullName}' party. Destroying the new transport." );
                    }
                    await SafeDestroyTransportAsync( monitor, remoteTransport.Transport );
                }
            }
        }

    }
}
