using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.KeyManagement;

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
                if( !PlugLocalAndRemotes( context, local ) ) return Task.FromResult( false );
            }
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
                success = PlugLocalAndRemotes( context, local );
            }
        }
        else
        {
            IRemoteParty remote = (IRemoteParty)party;
            if( IsAllowedFeature( remote ) )
            {
                var localKeys = remote.Owner.GetFeature<LocalKeys>();
                if( localKeys != null )
                {
                    success = PlugRemote( context, localKeys, remote );
                }
            }
        }
        return Task.FromResult( success );
    }

    protected override Task TeardownAsync( FeatureLifetimeContext context )
    {
        var locals = ((IEnumerable<ILocalParty>)ApplicationIdentityService.TenantDomains).Prepend( ApplicationIdentityService );
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

    bool PlugLocalAndRemotes( FeatureLifetimeContext context, ILocalParty local )
    {
        bool success = true;
        try
        {
            var localKeys = new LocalKeys.Builder( local, _protectorProvider ).Build( context.Monitor );
            local.AddFeature( localKeys );
            foreach( var r in local.Remotes )
            {
                if( IsAllowedFeature( r ) )
                {
                    success &= PlugRemote( context, localKeys, r );
                }
            }
            return success;
        }
        catch( Exception ex )
        {
            context.Monitor.Error( $"While initializing LocalKeys feature for '{local}'.", ex );
            return false;
        }
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

    bool PlugRemote( FeatureLifetimeContext context, LocalKeys localKeys, IRemoteParty remote )
    {
        try
        {
            var remoteKeys = new RemoteKeys.Builder( localKeys, remote ).Build( context.Monitor );
            remote.AddFeature( remoteKeys );
            return true;
        }
        catch( Exception ex )
        {
            context.Monitor.Error( $"While initializing RemoteKeys feature for '{remote}'.", ex );
            return false;
        }
    }

    static void UnplugRemote( FeatureLifetimeContext context, IRemoteParty r )
    {
        r.GetFeature<RemoteKeys>()?.TrustedIdentity?.OnTeardown();
    }

}
