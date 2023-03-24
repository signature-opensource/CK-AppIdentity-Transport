using CK.Core;
using CK.PerfectEvent;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.TransportLayer
{
    public sealed partial class TransportManager : MicroAgent
    {
        readonly AppIdentityAgent _agent;
        // Heart beats handles the BackTask list.
        readonly Timer _heartbeat;
        readonly BackTask.List _backTasks;
        readonly BackTask.Head _headIncomingConnection;
        readonly BackTask.Head _headOutgoingConnection;

        // Message factory for sending connection messages.
        readonly OutgoingMessageFactory _messageSendingFactory;
        readonly List<InitialMessage> _waitingList;
        readonly PerfectEventSender<InitialMessage> _waitingListChanged;

        internal TransportManager( AppIdentityAgent agent )
            : base( "CK.AppIdentity.PocoChannel.ConnectionManager" )
        {
            _agent = agent;
            _messageSendingFactory = new OutgoingMessageFactory();
            _waitingList = new List<InitialMessage>();
            _waitingListChanged = new PerfectEventSender<InitialMessage>();
            _backTasks = new BackTask.List( this );
            _headIncomingConnection = BackTask.Head.Create<IncomingConnectionBackTask>();
            _headOutgoingConnection = BackTask.Head.Create<OutgoingConnectionBackTask>();
            _heartbeat = new Timer( OnTimer, this, 1000, 1000 );

        }

        static void OnTimer( object? state ) => Unsafe.As<TransportManager>( state! ).PushTypedJob( DBNull.Value );

        internal bool Start() => TryStart() == RunningStatus.Running;

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
        /// Gets the message factory for outgoing messages.
        /// </summary>
        internal OutgoingMessageFactory MessageSendingFactory => _messageSendingFactory;

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityService"/> agent.
        /// </summary>
        public AppIdentityAgent ApplicationIdentityAgent => _agent;

        internal void TryConnectTo( IRemoteParty remote, TransportTypeAddress target )
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

        internal void IncomingAcceptedTransport( IRemoteParty remote, Transport incoming )
        {
            PushTypedJob( new IncomingAcceptedTransportJob( remote, incoming ) );
        }

        internal void CondemnTransport( ITransport transport, TransportMessage[]? byeByeMessages = null )
        {
            PushTypedJob( new CondemnTransportJob( transport, byeByeMessages ) );
        }

        // A new incoming Transport from a TransportListener is directly the Transport object.
        // An unknown incoming connection is directly the InitialMessage.
        sealed record class TryConnectToJob( IRemoteParty remote, TransportTypeAddress target );
        sealed record class IncomingAcceptedTransportJob( IRemoteParty Remote, Transport Transport );
        sealed record class CondemnTransportJob( ITransport Transport, TransportMessage[]? byeByeMessage );

        protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case DBNull:
                    using( monitor.OpenTrace( $"TransportManager heartbeat ({_backTasks.Count} background tasks to check)." ) )
                    {
                        _backTasks.OnHeartBeat( monitor );
                    }
                    return default;
                case TryConnectToJob c:
                    _backTasks.Add<OutgoingConnectionBackTask>( _headOutgoingConnection, back => back.Setup( this, c.remote, c.target ), 1 );
                    return default;
                case Transport t:
                    Debug.Assert( t.Listener != null, "This is necessarily an incoming connection created by a listener." );
                    _backTasks.Add<IncomingConnectionBackTask>( _headIncomingConnection, back => back.Setup( this, t ), 2 );
                    return default;
                case InitialMessage m:
                    return HandleUnknownIncomingRemote( monitor, m );
                case IncomingAcceptedTransportJob j:
                    return HandleIncomingAcceptedTransport( monitor, j );
                case CondemnTransportJob j:
                    return HandleCondemnTransport( monitor, j );
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        async ValueTask HandleCondemnTransport( IActivityMonitor monitor, CondemnTransportJob j )
        {
            using( monitor.OpenTrace( $"Condemning transport '{j.Transport}'." ) )
            {
                // TODO: handle ByeBye messages (with a back task).
                await DestroyTransportAsync( monitor, j.Transport );
            }
        }

        async Task DestroyTransportAsync( IActivityMonitor monitor, ITransport t )
        {
            try
            {
                if( t is IAsyncDisposable a )
                {
                    await a.DisposeAsync().ConfigureAwait( false );
                }
                else if( t is IDisposable d )
                {
                    d.Dispose();
                }
                ((Transport)t).DisposeMessageReceiveFactory();
            }
            catch( Exception ex )
            {
                monitor.Error( "While destroying transport.", ex );
            }
        }

        async ValueTask HandleUnknownIncomingRemote( IActivityMonitor monitor, InitialMessage initialMessage )
        {
            _waitingList.Add( initialMessage );
            await _waitingListChanged.SafeRaiseAsync( monitor, initialMessage );
        }

        async ValueTask HandleIncomingAcceptedTransport( IActivityMonitor monitor, IncomingAcceptedTransportJob remoteTransport )
        {
            var channel = remoteTransport.Remote.GetFeature<TransportFeature>();
            if( channel != null )
            {
                channel.OnNewTransport( monitor, remoteTransport.Transport );
            }
            else
            {
                monitor.Error( $"Transport feature has been removed from '{remoteTransport.Remote.FullName}' party. Destroying the incoming transport." );
                await DestroyTransportAsync( monitor, remoteTransport.Transport );
            }
        }

    }
}
