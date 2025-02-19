using CK.Core;

namespace CK.AppIdentity.TransportLayer;

sealed class DelayedKillTransportBackTask : BackTask<TransportManager>
{
    Transport? _transport;
    int _outgoingReconnectDelay;

    public void OnInitialize( Transport transport, int outgoingReconnectDelay )
    {
        _transport = transport;
        _outgoingReconnectDelay = outgoingReconnectDelay;
        NextCheckDelay = 1;
    }

    public override void Check( IActivityMonitor monitor, int previousCheckDelay )
    {
        Throw.DebugAssert( _transport != null );
        TaskManager.Host.KillTransport( _transport, _outgoingReconnectDelay );
    }

    public override void OnDestroy( IActivityMonitor monitor )
    {
    }

    public override void Reset()
    {
        _transport = null;
    }
}
