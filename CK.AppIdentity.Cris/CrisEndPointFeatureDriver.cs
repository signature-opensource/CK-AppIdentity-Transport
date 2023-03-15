using CK.Core;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    public sealed class CrisEndPointFeatureDriver : ApplicationIdentityFeatureDriver
    {
        [AllowNull]
        AppIdentityAgent _appIdentityAgent;

        public CrisEndPointFeatureDriver( ApplicationIdentityService s )
            : base( s, true )
        {
        }

        protected override Task<bool> InitializeAsync( IActivityMonitor monitor, AppIdentityAgent appIdentityAgent )
        {
            _appIdentityAgent = appIdentityAgent;
            // We always add the DomainCrisEndPoint feature (pure events) on the root domain
            // and on subordinate domains: it is the RemoteCrisEndPoint that are added or not.
            DomainCrisEndPoint rootEvents = new DomainCrisEndPoint( ApplicationIdentity );
            ApplicationIdentity.AddFeature( rootEvents );
            foreach( var r in ApplicationIdentity.Remotes )
            {
                bool isAllowed = r.Configuration.IsAllowedFeature( FeatureName, IsRootAllowed );
                if( r.DomainApplicationIdentity != null )
                {
                    var domainEvents = new DomainCrisEndPoint( r, rootEvents );
                    r.AddFeature( domainEvents );
                    foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                    {
                        if( rSub.DomainName != CoreApplicationIdentity.DefaultDomainName
                            && rSub.Configuration.IsAllowedFeature( FeatureName, isAllowed ) )
                        {
                            rSub.AddFeature( new RemoteCrisEndPoint( appIdentityAgent, rSub, domainEvents ) );
                        }
                    }
                }
                else
                {
                    if( r.DomainName != CoreApplicationIdentity.DefaultDomainName
                        && r.Configuration.IsAllowedFeature( FeatureName, isAllowed ) )
                    {
                        r.AddFeature( new RemoteCrisEndPoint( appIdentityAgent, r, rootEvents ) );
                    }
                }
            }
            return Task.FromResult( true );
        }
    }
}
