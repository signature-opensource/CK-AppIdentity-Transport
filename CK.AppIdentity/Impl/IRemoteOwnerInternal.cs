using CK.Core;
using CK.PerfectEvent;

namespace CK.AppIdentity
{
    interface IRemoteOwnerInternal : IRemoteOwner
    {
        new PerfectEventSender<IRemote> RemotesChanged { get; }

        void RemoveDestroyed( IRemote destroyed );

        void OnSuccessAddRemoteAsync( IActivityMonitor monitor, IRemote r );

    }
}
