using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.Cris;


public sealed partial class CrisChannelFeature : ChannelFeature
{
    readonly PocoDirectory _pocoDirectory;
    readonly IncomingCommandExecutor _executor;
    readonly OutgoingCache _outgoingRequestCache;
    readonly PerfectEventSender<IOutgoingCrisPoco, IEvent> _onEvent;
    readonly ConcurrentQueue<OutgoingCrisPoco> _pendingRequest;

    public CrisChannelFeature( TransportFeature transportFeature,
                               PocoDirectory pocoDirectory,
                               CrisExecutionHost executionHost,
                               IDIContainer<AppIdentityDIContainerDefinition.Data> endpoint )
        : base( transportFeature )
    {
        _pocoDirectory = pocoDirectory;
        _onEvent = new PerfectEventSender<IOutgoingCrisPoco, IEvent>();
        _outgoingRequestCache = new OutgoingCache( pocoDirectory.Find<ICrisResultError>()!, _onEvent );
        _pendingRequest = new ConcurrentQueue<OutgoingCrisPoco>();
        _executor = new IncomingCommandExecutor( this, executionHost, endpoint );
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

    public IOutgoingCommand<T> SendCommand<T>( IActivityMonitor monitor, T command, string? authToken = null ) where T : class, IAbstractCommand
    {
        var request = _outgoingRequestCache.CreateCommand( monitor, command, authToken );
        var r = (OutgoingCrisPoco)request;
        var h = CurrentHandler;
        if( h == null || !h.TrySend( (OutgoingCrisPoco)request, true ) )
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

    void SubmitPendingRequests( IActivityMonitor monitor )
    {
        int count = 0;
        while( _pendingRequest.TryPeek( out OutgoingCrisPoco? r ) )
        {
            var h = CurrentHandler;
            if( h != null && h.TrySend( r ) )
            {
                _pendingRequest.TryDequeue( out _ );
            }
            else break;
        }
        if( count != 0 ) monitor.Info( $"Submitted {count} pending requests." );
    }

}
