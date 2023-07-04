using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.KeyManagement
{
    public class KeyManagementFeatureDriver : ApplicationIdentityFeatureDriver
    {
        readonly IDataProtectionProvider _protectorProvider;

        public KeyManagementFeatureDriver( ApplicationIdentityService s, IDataProtectionProvider protectorProvider )
            : base( s, true )
        {
            _protectorProvider = protectorProvider;
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
        {
            var locals = ((IEnumerable<ILocalParty>)ApplicationIdentityService.TenantDomains).Prepend( ApplicationIdentityService );
            foreach( var local in locals )
            {
                if( IsAllowedFeature( local ) )
                {
                    if( !PlugLocal( context, local ) ) return Task.FromResult( false );
                }
                if( !PlugLocalRemotes( context, local ) ) return Task.FromResult( false );
            }
            return Task.FromResult( true );
        }

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
        {
            bool success = true;
            if( party is ILocalParty local )
            {
                if( IsAllowedFeature( local ) )
                {
                    success = PlugLocal( context, local );
                }
                success &= PlugLocalRemotes( context, local );
            }
            else
            {
                IRemoteParty remote = (IRemoteParty)party;
                if( IsAllowedFeature( remote ) )
                {
                    success = PlugRemote( context, remote );
                }
            }
            return Task.FromResult( success );
        }

        protected override Task TeardownAsync( FeatureLifetimeContext context )
        {
            var locals = ((IEnumerable<ILocalParty>)ApplicationIdentityService.TenantDomains)
                                                    .Prepend( ApplicationIdentityService );
            foreach( var local in locals )
            {
                UnplugLocalAndRemotes( context, local );
            }
            return Task.CompletedTask;
        }

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
        {
            if( party is ILocalParty local )
            {
                UnplugLocalAndRemotes( context, local );
            }
            else
            {
                UnplugRemote( context, (IRemoteParty)party );
            }
            return Task.CompletedTask;
        }

        bool PlugLocal( FeatureLifetimeContext context, ILocalParty local )
        {
            var localKeys = new LocalKeys.Builder( local, _protectorProvider ).Build( context.Monitor );
            local.AddFeature( localKeys );
            return true;
        }

        bool PlugLocalRemotes( FeatureLifetimeContext context, ILocalParty local )
        {
            foreach( var r in local.Remotes )
            {
                if( IsAllowedFeature( r ) )
                {
                    if( !PlugRemote( context, r ) ) return false;
                }
            }
            return true;
        }

        static void UnplugLocalAndRemotes( FeatureLifetimeContext context, ILocalParty local )
        {
            var localKeys = local.GetFeature<LocalKeys>();
            if( localKeys != null )
            {
                localKeys.OnTearDown( context.Monitor );
                foreach( var r in local.Remotes )
                {
                    UnplugRemote( context, r );
                }
            }
        }

        bool PlugRemote( FeatureLifetimeContext context, IRemoteParty remote )
        {
            var remoteKeys = new RemoteKeys.Builder( remote ).Build( context.Monitor );
            remote.AddFeature( remoteKeys );
            return true;
        }

        static void UnplugRemote( FeatureLifetimeContext context, IRemoteParty r )
        {
            r.GetFeature<RemoteKeys>()?.TrustedIdentity?.OnTeardown();
        }

    }
}
