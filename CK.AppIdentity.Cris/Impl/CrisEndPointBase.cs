using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{

    abstract class CrisEndPointBase : ICrisEndPointEvents
    {
        IAppIdentityObject _object;
        PerfectEventSender<IRemoteParty> _isConnectedChanged;
        PerfectEventSender<IRemoteParty, ICommand<NoWaitResult>> _onEventReceived;
        PerfectEventSender<IRemoteParty, ICommand> _onCommandReceived;

        protected CrisEndPointBase( IAppIdentityObject o, CrisEndPointBase? parent )
        {
            _object = o;
            _isConnectedChanged = new PerfectEventSender<IRemoteParty>();
            _onEventReceived = new PerfectEventSender<IRemoteParty, ICommand<NoWaitResult>>();
            _onCommandReceived = new PerfectEventSender<IRemoteParty, ICommand>();
            if( parent != null )
            {
                // Relationship from child to parent is stable. We'll never need to
                // dispose these relays.
                _isConnectedChanged.CreateRelay( parent._isConnectedChanged );
                _onEventReceived.CreateRelay( parent._onEventReceived );
                _onCommandReceived.CreateRelay( parent._onCommandReceived );
            }
        }

        protected IAppIdentityObject AppIdentityObject => _object;

        public PerfectEvent<IRemoteParty> IsConnectedChanged => _isConnectedChanged.PerfectEvent;

        public PerfectEvent<IRemoteParty, ICommand<NoWaitResult>> OnEventReceived => _onEventReceived.PerfectEvent;

        public PerfectEvent<IRemoteParty, ICommand> OnCommandReceived => _onCommandReceived.PerfectEvent;

        public abstract ValueTask SendEventAsync( IActivityMonitor monitor, ICommand<NoWaitResult> commandEvent );
    }
}
