using CK.Core;
using CK.PerfectEvent;

namespace CK.AppIdentity.PocoChannel
{
    public interface IPocoChannel
    {
        bool IsConnected { get; }

        IRemoteParty Party { get; }

        PerfectEvent<IPocoChannel> IsConnectedChanged { get; }

        ValueTask SendAsync( IActivityMonitor monitor, IPoco poco );

        PerfectEvent<IPocoChannel, IPoco> ReceivedPoco { get; }
    }
}
