using CK.Core;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    public sealed class CrisEndPointFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public CrisEndPointFeatureDriver( ApplicationIdentityService s )
            : base( s, true )
        {
        }

        protected override Task<bool> InitializeAsync( FeatureInitializatonContext context )
        {
            // We always add the DomainCrisEndPoint feature (pure events) on the root domain
            // and on subordinate domains: it is the RemoteCrisEndPoint that are added or not.
            DomainCrisEndPoint rootEvents = new DomainCrisEndPoint( ApplicationIdentityService );
            ApplicationIdentityService.AddFeature( rootEvents );
            foreach( var r in ApplicationIdentityService.Remotes )
            {
                if( r.DomainApplicationIdentity != null )
                {
                    var domainEvents = new DomainCrisEndPoint( r, rootEvents );
                    r.AddFeature( domainEvents );
                    foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                    {
                        if( rSub.DomainName != CoreApplicationIdentity.DefaultDomainName
                            && IsAllowedFeature(rSub) )
                        {
                            rSub.AddFeature( new RemoteCrisEndPoint( context.Agent, rSub, domainEvents ) );
                        }
                    }
                }
                else
                {
                    if( r.DomainName != CoreApplicationIdentity.DefaultDomainName
                        && IsAllowedFeature(r) )
                    {
                        r.AddFeature( new RemoteCrisEndPoint( context.Agent, r, rootEvents ) );
                    }
                }
            }
            return Task.FromResult( true );
        }

        protected override Task<bool> InitializeDynamicRemoteAsync( FeatureInitializatonContext context, IRemoteParty remoteParty )
        {
            throw new System.NotImplementedException();
        }
    }
}
