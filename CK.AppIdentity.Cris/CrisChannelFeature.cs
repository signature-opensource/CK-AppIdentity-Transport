using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.Cris
{

    public sealed partial class CrisChannelFeature : ChannelFeature
    {
        readonly PocoDirectory _pocoDirectory;
        readonly CrisChannelExecutor _executor;
        readonly IAuthenticationInfoTokenService _tokenService;
        readonly ICrisExecutorEndPoint<CrisChannelExecutorRequest> _executorEndpoint;
        readonly OutgoingRequestCache _outgoingRequestCache;
        readonly PerfectEventSender<IOutgoingRequest, IEvent> _onEvent;
        readonly ConcurrentQueue<OutgoingRequest> _pendingRequest;

        public CrisChannelFeature( TransportFeature transportFeature,
                                   PocoDirectory pocoDirectory,
                                   CrisChannelExecutor executor,
                                   IAuthenticationInfoTokenService tokenService )
            : base( transportFeature )
        {
            _pocoDirectory = pocoDirectory;
            _executor = executor;
            _tokenService = tokenService;
            _onEvent = new PerfectEventSender<IOutgoingRequest, IEvent>();
            _outgoingRequestCache = new OutgoingRequestCache( pocoDirectory.Find<ICrisResultError>()!, _onEvent );
            _pendingRequest = new ConcurrentQueue<OutgoingRequest>();
            _executorEndpoint = new CrisChannelEndpoint( this );
        }

        new Protocol? CurrentHandler => Unsafe.As<Protocol?>( base.CurrentHandler );

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            return new Protocol( this, ref c );
        }

        protected override void OnCurrentHandlerChanged( IActivityMonitor monitor, PeerProtocolHandler? previous, PeerProtocolHandler? current )
        {
            if( previous == null && current != null )
            {
                SubmitPendingRequests( monitor );
            }
        }

        void SubmitPendingRequests( IActivityMonitor monitor )
        {
            int count = 0;
            while( _pendingRequest.TryPeek( out var r ) )
            {
                var h = CurrentHandler;
                if( h != null && h.TrySendRequest( r, highPriority: r.Payload is IEvent ) )
                {
                    _pendingRequest.TryDequeue( out _ );
                }
                else break;
            }
            if( count != 0 ) monitor.Info( $"Submitted {count} pending requests." );
        }

        public IEventRequest<T> SendEvent<T>( IActivityMonitor monitor, T e, string? authToken = null ) where T : class, IEvent
        {
            var request = _outgoingRequestCache.CreateEvent( monitor, e, authToken );
            var r = (OutgoingRequest)request;
            var h = CurrentHandler;
            if( h == null || !h.TrySendRequest( r, highPriority: true ) )
            {
                monitor.Warn( $"No connection to '{Transport.Party.FullName}'. Event '{e.CrisPocoModel.PocoName}' cannot be sent immediately." );
                _pendingRequest.Enqueue( r );
            }
            else
            {
                SubmitPendingRequests( monitor );
            }
            return request;
        }

        public ICommandRequest<T> SendCommand<T>( IActivityMonitor monitor, T command, string? authToken = null ) where T : class, IAbstractCommand
        {
            var request = _outgoingRequestCache.CreateCommand( monitor, command, authToken );
            var r = (OutgoingRequest)request;
            var h = CurrentHandler;
            if( h == null || !h.TrySendRequest( (OutgoingRequest)request, true ) )
            {
                monitor.Warn( $"No connection to '{Transport.Party.FullName}'. Command '{command.CrisPocoModel.PocoName}' cannot be sent immediately." );
                _pendingRequest.Enqueue( r );
            }
            else
            {
                SubmitPendingRequests( monitor );
            }
            return request;
        }

    }
}
