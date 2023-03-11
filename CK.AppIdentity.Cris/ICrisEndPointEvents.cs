using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    public interface ICrisEndPointEvents
    {
        PerfectEvent<IRemoteParty> IsConnectedChanged { get; }

        PerfectEvent<IRemoteParty, ICommand<NoWaitResult>> OnEventReceived { get; }

        PerfectEvent<IRemoteParty, ICommand> OnCommandReceived { get; }

        ValueTask SendEventAsync( IActivityMonitor monitor, ICommand<NoWaitResult> commandEvent );
    }
}
