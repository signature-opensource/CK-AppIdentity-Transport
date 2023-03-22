using CK.Core;
using CK.Cris;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    class DomainCrisEndPoint : CrisEndPointBase
    {
        readonly IApplicationIdentity _appIdentity;

        public DomainCrisEndPoint( IRemoteParty remote, CrisEndPointBase? parent )
            : base( remote, parent )
        {
            Debug.Assert( remote.DomainApplicationIdentity != null );
            _appIdentity = remote.DomainApplicationIdentity;
        }

        public DomainCrisEndPoint( ApplicationIdentityService root )
            : base( root, null )
        {
            _appIdentity = root;
        }

        public override async ValueTask SendEventAsync( IActivityMonitor monitor, ICommand<NoWaitResult> commandEvent )
        {
            foreach( var r in _appIdentity.Remotes )
            {
                var f = r.GetFeature<ICrisEndPointEvents>();
                if( f != null )
                {
                    await f.SendEventAsync( monitor, commandEvent );
                }
            }
        }
    }
}
