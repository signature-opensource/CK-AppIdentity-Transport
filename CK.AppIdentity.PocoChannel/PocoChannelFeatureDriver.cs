using CK.Core;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading.Tasks;

namespace CK.AppIdentity.PocoChannel
{
    public sealed class PocoChannelFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public PocoChannelFeatureDriver( ApplicationIdentityService s )
            : base( s, true )
        {
        }

        protected override Task<bool> InitializeAsync( FeatureInitializatonContext context )
        {
            bool success = true;
            foreach( var r in ApplicationIdentityService.Remotes )
            {
                if( r.DomainApplicationIdentity != null )
                {
                    foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                    {
                        if( IsAllowedFeature( rSub ) )
                        {
                            success &= PlugFeature( context.Monitor, rSub );
                        }
                    }
                }
                else
                {
                    if( IsAllowedFeature( r ) )
                    {
                        success &= PlugFeature( context.Monitor, r );
                    }
                }
            }
            return Task.FromResult( success );

        }

        protected override Task<bool> InitializeDynamicRemoteAsync( DynamicRemoteInitializatonContext context )
        {
            throw new NotImplementedException();
        }

        static bool PlugFeature( IActivityMonitor monitor, IRemoteParty r )
        {
            // Skip "Undefined" but this is not an error.
            if( r.DomainName != CoreApplicationIdentity.DefaultDomainName )
            {
                return false;
            }
            return true;
        }

    }
}
