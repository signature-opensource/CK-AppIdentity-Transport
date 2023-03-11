using CK.Core;
using CK.PerfectEvent;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace CK.AppIdentity.PocoChannel
{

    sealed class RemotePocoChannel : IPocoChannel
    {
        readonly IRemoteParty _remote;
        readonly PerfectEventSender<IPocoChannel> _isConnectedChanged;
        readonly PerfectEventSender<IPocoChannel, IPoco> _receivedPoco;
        bool _isConnected;

        public RemotePocoChannel( IRemoteParty remote )
        {
            _remote = remote;
            _isConnectedChanged = new PerfectEventSender<IPocoChannel>();
            _receivedPoco = new PerfectEventSender<IPocoChannel, IPoco>();
        }

        public bool IsConnected => _isConnected;

        public IRemoteParty Party => _remote;

        public PerfectEvent<IPocoChannel> IsConnectedChanged => _isConnectedChanged.PerfectEvent;

        public PerfectEvent<IPocoChannel, IPoco> ReceivedPoco => _receivedPoco.PerfectEvent;

        public ValueTask SendAsync( IActivityMonitor monitor, IPoco poco )
        {
            throw new NotImplementedException();
        }
    }

    public sealed class PocoChannelFeatureDriver : ApplicationIdentityFeatureDriver
    {
        [AllowNull]
        AppIdentityAgent _appIdentityAgent;
        List<string>? _noPocoAlias;

        public PocoChannelFeatureDriver( ApplicationIdentityService s )
            : base( s )
        {
        }

        /// <summary>
        /// Adds aliases to "NoPoco" boolean configuration key.
        /// </summary>
        public List<string> NoPocoAlias => _noPocoAlias ??= new List<string>();

        protected override Task InitializeAsync( IActivityMonitor monitor, AppIdentityAgent appIdentityAgent )
        {
            _appIdentityAgent = appIdentityAgent;
            foreach( var r in ApplicationIdentity.Remotes )
            {
                if( r.DomainApplicationIdentity != null )
                {
                    foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                    {
                        rSub.AddFeature( new RemotePocoChannel( rSub ) );
                    }
                }
                else
                {
                    foreach( var rSub in ApplicationIdentity.Remotes )
                    {
                        rSub.AddFeature( new RemotePocoChannel( rSub ) );
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
