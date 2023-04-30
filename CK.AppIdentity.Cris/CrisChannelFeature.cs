using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.Cris
{

    public sealed partial class CrisChannelFeature : ChannelFeature
    {
        readonly PocoDirectory _pocoDirectory;
        readonly CrisChannelExecutor _executor;
        readonly IAuthenticationInfoTokenService _tokenService;
        readonly ICrisExecutorEndPoint<CrisChannelExecutorRequest> _executorEndpoint;

        public CrisChannelFeature( TransportFeature transportFeature,
                                   PocoDirectory pocoDirectory,
                                   CrisChannelExecutor executor,
                                   IAuthenticationInfoTokenService tokenService )
            : base( transportFeature )
        {
            _pocoDirectory = pocoDirectory;
            _executor = executor;
            _tokenService = tokenService;
            _executorEndpoint = new CrisChannelEndpoint( this );
        }

        new Protocol? CurrentHandler => Unsafe.As<Protocol?>( base.CurrentHandler );

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            return new Protocol( this, ref c );
        }

        public IEventRequest<T>? TrySendEvent<T>( IActivityMonitor monitor, T e, string? authToken = null ) where T : class, IEvent
        {
            var h = CurrentHandler;
            if( h != null )
            {
                var request = OutgoingRequest.CreateEvent<T>( monitor, e );
                var message = h.CreateRequestMessage( request.IssuerToken, e, authToken );
                message.Source = request;
                if( h.TryEnqueue( message ) )
                {
                    return request;
                }
                message.Dispose();
            }
            return null;
        }

        public ICommandRequest<T>? TrySendCommand<T>( IActivityMonitor monitor, T command, string? authToken = null ) where T : class, IAbstractCommand
        {
            var h = CurrentHandler;
            if( h != null )
            {
                var request = OutgoingRequest.CreateCommand( monitor, command );
                var message = h.CreateRequestMessage( request.IssuerToken, command, authToken );
                if( h.TryEnqueue( message ) )
                {
                    return request;
                }
                message.Dispose();
            }
            return null;
        }

    }
}
