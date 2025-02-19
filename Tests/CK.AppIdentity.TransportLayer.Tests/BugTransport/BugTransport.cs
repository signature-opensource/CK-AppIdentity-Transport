using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

public class BugTransport : Transport
{
    readonly BugTransportTypeService.BugType _bugType;

    public BugTransport( TransportTypeAddress targetAddress, IRemoteKeys remoteKeys )
        : base( targetAddress, remoteKeys, targetAddress.TypedAddress.ToString() )
    {
        _bugType = (BugTransportTypeService.BugType)targetAddress.TypedAddress;
    }

    protected override ValueTask DisposeAsync( IActivityMonitor monitor )
    {
        if( (_bugType & BugTransportTypeService.BugType.DisposeTransportInline) != 0 )
        {
            throw new Exception( "Bug: DisposeTransportInline." );
        }

        if( (_bugType & BugTransportTypeService.BugType.DisposeTransport) != 0 )
        {
            return ValueTask.FromException( new Exception( "Bug: DisposeTransport." ) );
        }

        return default;
    }

    protected override async ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellation )
    {
        if( (_bugType & BugTransportTypeService.BugType.TransportReadInline) != 0 )
        {
            throw new Exception( "Bug: TransportReadInline." );
        }
        await Task.Delay( 20, cancellation );
        if( (_bugType & BugTransportTypeService.BugType.TransportRead) != 0 )
        {
            throw new Exception( "Bug: TransportRead." );
        }
        return 1 + Random.Shared.Next( buffer.Length - 1 );
    }

    protected override async ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken )
    {
        if( (_bugType & BugTransportTypeService.BugType.TransportWriteInline) != 0 )
        {
            throw new Exception( "Bug: TransportWriteInline." );
        }
        await Task.Delay( 20, cancellationToken );
        if( (_bugType & BugTransportTypeService.BugType.TransportWrite) != 0 )
        {
            throw new Exception( "Bug: TransportWrite." );
        }
    }
}
