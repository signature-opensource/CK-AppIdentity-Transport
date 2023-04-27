using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.Cris
{

    public sealed partial class CrisEndPointFeature : ChannelFeature
    {
        readonly PocoDirectory _pocoDirectory;
        readonly IServiceProvider _serviceProvider;

        public CrisEndPointFeature( TransportFeature transportFeature, PocoDirectory pocoDirectory, IServiceProvider serviceProvider )
            : base( transportFeature )
        {
            _pocoDirectory = pocoDirectory;
            _serviceProvider = serviceProvider;
        }

        new Protocol? CurrentHandler => Unsafe.As<Protocol?>( base.CurrentHandler );

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            return new Protocol( this, ref c );
        }

        public ICommandRequest<T>? TrySendCommand<T>( IActivityMonitor monitor, T command, string? authToken ) where T : class, ICommand
        {
            var h = CurrentHandler;
            if( h != null )
            {
                var depToken = monitor.CreateDependentToken( command.CommandModel.CommandName );
                var request = new CommandRequest<T>( command, depToken, authToken );
                var message = h.CreateRequestMessage( depToken, command, authToken );
                if( h.TryEnqueue( message ) )
                {
                    return request;
                }
                message.Dispose();
            }
            return null;
        }

        public ICommandRequest<T,TResult>? TrySendCommand<T, TResult>( IActivityMonitor monitor, T command, string? authToken ) where T : class, ICommand<TResult>
        {
            var h = CurrentHandler;
            if( h != null )
            {
                var depToken = monitor.CreateDependentToken( command.CommandModel.CommandName );

                var message = h.CreateRequestMessage( depToken, command, authToken );
                if( h.TryEnqueue( message ) )
                {
                    return null;
                }
                message.Dispose();
            }
            return null;
        }

    }
}
