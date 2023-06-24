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
        readonly IncomingCommandExecutor _executor;
        readonly IAuthenticationInfoTokenService _tokenService;
        readonly OutgoingCommandCache _outgoingRequestCache;
        readonly PerfectEventSender<IOutgoingCommand, IEvent> _onEvent;
        readonly ConcurrentQueue<OutgoingCommand> _pendingRequest;

        public CrisChannelFeature( TransportFeature transportFeature,
                                   PocoDirectory pocoDirectory,
                                   IEndpointType<AppIdentityEndpointDefinition.Data> endpoint,
                                   CrisExecutionHost executionHost,
                                   IAuthenticationInfoTokenService tokenService )
            : base( transportFeature )
        {
            _pocoDirectory = pocoDirectory;
            _executor = new IncomingCommandExecutor( executionHost, endpoint );
            _tokenService = tokenService;
            _onEvent = new PerfectEventSender<IOutgoingCommand, IEvent>();
            _outgoingRequestCache = new OutgoingCommandCache( pocoDirectory.Find<ICrisResultError>()!, _onEvent );
            _pendingRequest = new ConcurrentQueue<OutgoingCommand>();
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

        public IOutgoingCommand<T> SendCommand<T>( IActivityMonitor monitor, T command, string? authToken = null ) where T : class, IAbstractCommand
        {
            var request = _outgoingRequestCache.CreateCommand( monitor, command, authToken );
            var r = (OutgoingCommand)request;
            var h = CurrentHandler;
            if( h == null || !h.TrySendRequest( (OutgoingCommand)request, true ) )
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
