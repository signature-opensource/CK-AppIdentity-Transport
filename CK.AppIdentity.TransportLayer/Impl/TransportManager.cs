using CK.Core;
using CK.PerfectEvent;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.TransportLayer
{
    public sealed partial class TransportManager : MicroAgent
    {
        readonly AppIdentityAgent _agent;
        // Heart beats handles the BackTask list.
        readonly Timer _heartbeat;
        readonly BackTask.List _backTasks;
        List<(ITransport Transport, Task<string?> OperationError, DateTime Expires, bool AlwaysDestroy)> _backgroundTaskList;


        // Message factory for sending connection messages.
        readonly TransportMessageFactory _messageSendingFactory;
        readonly List<InitialMessage> _waitingList;
        readonly PerfectEventSender<InitialMessage> _waitingListChanged;

        internal TransportManager( AppIdentityAgent agent )
            : base( "CK.AppIdentity.PocoChannel.ConnectionManager" )
        {
            _agent = agent;
            _messageSendingFactory = new TransportMessageFactory();
            _waitingList = new List<InitialMessage>();
            _waitingListChanged = new PerfectEventSender<InitialMessage>();
            _backTasks = new BackTask.List( this );
            _backgroundTaskList = new List<(ITransport Transport, Task<string?> OperationError, DateTime Expires, bool AlwaysDestroy)>();
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

        public new void PushTypedJob( object job ) => base.PushTypedJob( job );

        /// <summary>
        /// Gets the message factory for outgoing messages.
        /// </summary>
        public TransportMessageFactory MessageSendingFactory => _messageSendingFactory;

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityService"/> agent.
        /// </summary>
        public AppIdentityAgent ApplicationIdentityAgent => _agent;

        // An IncomingConnection is directly the Transport object.
        record class UnknownIncomingRemoteJob( Transport Transport, InitialMessage InitialMessage );
        record class IncomingAcceptedTransportJob( IRemoteParty Remote, Transport Transport );
        public record class CondemnTransportJob( ITransport Transport, TransportMessage? ByeByeMessage = null );

        protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case DBNull: return HandleHeartBeat( monitor );
                case Transport t:
                    // New Transport:
                    if( t.Listener != null )
                    {
                        _backgroundTaskList.Add( (t, HandleIncomingTransportStartAsync( t ), DateTime.UtcNow.AddSeconds( 2 ), false) );
                    }
                    return default;
                case UnknownIncomingRemoteJob j:
                    return HandleUnknownIncomingRemote( monitor, j );
                case IncomingAcceptedTransportJob j:
                    return HandleIncomingAcceptedTransport( monitor, j );
                case CondemnTransportJob j:
                    return HandleCondemnTransport( monitor, j );
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        async ValueTask HandleHeartBeat( IActivityMonitor monitor )
        {
            using( monitor.OpenTrace( $"TransportManager heartbeat ({_backTasks.Count} background tasks to check)." ) )
            {
                _backTasks.OnHeartBeat( monitor );
            }

            using( monitor.OpenTrace( $"ConnectionManager heartbeat ({_backgroundTaskList.Count} background tasks to check)." ) )
            {
                List<(ITransport Transport, Task<string?> OperationError, DateTime Expires, bool AlwaysDestroy)>? newList = null;
                var now = DateTime.UtcNow;
                foreach( var t in _backgroundTaskList )
                {
                    bool mustDestroy = false;
                    bool expired = t.Expires <= now;
                    if( t.OperationError.IsCompleted )
                    {
                        if( t.OperationError.Exception != null )
                        {
                            monitor.Warn( $"Background task failed.", t.OperationError.Exception );
                            mustDestroy = true;
                        }
                        else if( t.OperationError.Result != null )
                        {
                            monitor.Warn( $"Background task error: {t.OperationError.Result}." );
                            mustDestroy = true;
                        }
                        else
                        {
                            // The operation succeed, however we may still destroy the transport.
                            mustDestroy = t.AlwaysDestroy;
                        }
                    }
                    else if( expired )
                    {
                        // The operation is out of time. We must destroy it.
                        monitor.Warn( $"Background task timeout." );
                        mustDestroy = true;
                    }
                    else
                    {
                        // Pending operation: transfer to the new list.
                        newList ??= new();
                        newList.Add( t );
                    }
                    // If we must destroy the transport, do it.
                    if( mustDestroy )
                    {
                        await DestroyTransportAsync( monitor, t.Transport );
                    }
                }
                if( newList != null )
                {
                    monitor.Trace( $"{_backgroundTaskList.Count - newList.Count} tasks removed." );
                    _backgroundTaskList = newList;
                }
            }
        }

        async ValueTask HandleCondemnTransport( IActivityMonitor monitor, CondemnTransportJob j )
        {
            using( monitor.OpenTrace( $"Condemning transport '{j.Transport}'." ) )
            {
                if( j.ByeByeMessage != null )
                {
                    monitor.Trace( "Sending ByeBye message." );
                    var byeBye = j.Transport.SendAsync( j.ByeByeMessage )
                                    .AsTask()
                                    .ContinueWith( send =>
                                    {
                                        if( send.Exception != null ) return Task.FromException<string?>( send.Exception );
                                        return Task.FromResult<string?>( null );
                                    } )
                                    .Unwrap();
                    _backgroundTaskList.Add( (j.Transport, byeBye, DateTime.UtcNow.AddSeconds( 2 ), true) );
                }
                else
                {
                    await DestroyTransportAsync( monitor, j.Transport );
                }
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
    }
}
