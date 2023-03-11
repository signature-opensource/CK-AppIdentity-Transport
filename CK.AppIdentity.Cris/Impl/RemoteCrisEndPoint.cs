using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{

    sealed class RemoteCrisEndPoint : CrisEndPointBase, ICrisEndPointCommands
    {
        readonly AppIdentityAgent _appIdentityAgent;
        bool _isConnected;

        public RemoteCrisEndPoint( AppIdentityAgent appIdentityAgent, IRemoteParty remote, CrisEndPointBase parent )
            : base( remote, parent )
        {
            _appIdentityAgent = appIdentityAgent;
        }

        IRemoteParty Remote => Unsafe.As<IRemoteParty>( AppIdentityObject );

        public bool IsConnected { get; }

        public Task<ICrisResult> SendCommandAndWaitResultAsync( IActivityMonitor monitor, ICommand command )
        {
            throw new NotImplementedException();
        }

        public override ValueTask SendEventAsync( IActivityMonitor monitor, ICommand<NoWaitResult> commandEvent )
        {
            throw new NotImplementedException();
        }
    }
}
