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
            : base( s )
        {
        }

        protected override Task InitializeAsync( IActivityMonitor monitor, AppIdentityAgent appIdentityAgent )
        {
            _appIdentityAgent = appIdentityAgent;
            var rootEvents = new DomainCrisEndPoint( ApplicationIdentity );
            ApplicationIdentity.AddFeature( rootEvents );
            foreach( var r in ApplicationIdentity.Remotes )
            {
                if( r.DomainApplicationIdentity != null )
                {
                    var domainEvents = new DomainCrisEndPoint( r, rootEvents );
                    r.AddFeature( domainEvents );
                    foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                    {
                        rSub.AddFeature( new RemoteCrisEndPoint( appIdentityAgent, rSub, domainEvents ) );
                    }
                }
                else
                {
                    foreach( var rSub in ApplicationIdentity.Remotes )
                    {
                        rSub.AddFeature( new RemoteCrisEndPoint( appIdentityAgent, rSub, rootEvents ) );
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
