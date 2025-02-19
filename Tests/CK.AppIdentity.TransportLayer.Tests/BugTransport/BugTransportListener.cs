using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

public class BugTransportListener : TransportListener
{
    readonly BugTransportTypeService.BugType _bugType;

    public BugTransportListener( BugTransportTypeService transportType, object opaqueHandle, BugTransportTypeService.BugType bugType )
        : base( opaqueHandle, transportType )
    {
        _bugType = bugType;
    }

    public override string EndPointDescription => _bugType.ToString();

    protected override ValueTask DisposeAsync( IActivityMonitor monitor )
    {
        if( (_bugType & BugTransportTypeService.BugType.DisposeListenerInline) != 0 )
        {
            throw new Exception( "Bug: DisposeListenerInline." );
        }

        if( (_bugType & BugTransportTypeService.BugType.DisposeListener) != 0 )
        {
            return ValueTask.FromException( new Exception( "Bug: DisposeListener." ) );
        }

        return default;
    }

    protected override bool IsListeningAddress( object typedAddress )
    {
        return (BugTransportTypeService.BugType)typedAddress == _bugType;
    }
}
