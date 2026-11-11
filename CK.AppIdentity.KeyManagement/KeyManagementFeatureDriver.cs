using CK.Core;
using CK.PerfectEvent;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.KeyManagement;

public partial class KeyManagementFeatureDriver : ApplicationIdentityFeatureDriver
{
    readonly IDataProtectionProvider _protectorProvider;
    readonly ICoreKeyStore _keyStore;
    readonly PerfectEventSender<IdentityAlert> _alertRaised;
    readonly PerfectEventSender<ILocalKeys> _keyEventAppended;

    public KeyManagementFeatureDriver( ApplicationIdentityService s, IDataProtectionProvider protectorProvider, ICoreKeyStore keyStore )
        : base( s, true )
    {
        _protectorProvider = protectorProvider;
        _keyStore = keyStore;
        _alertRaised = new PerfectEventSender<IdentityAlert>();
        _keyEventAppended = new PerfectEventSender<ILocalKeys>();
    }

    /// <summary>
    /// Raised for every new <see cref="IdentityAlert"/> of any local party (the root one and the tenant
    /// domains), and again when a new remote confirms one. This is the one place to wire paging.
    /// <para>
    /// Raised from the heartbeat that follows the detection: the alert itself is logged at once, with
    /// the <see cref="IdentityAlert.LogTag"/>.
    /// </para>
    /// </summary>
    public PerfectEvent<IdentityAlert> AlertRaised => _alertRaised.PerfectEvent;

    /// <summary>
    /// Raised when the key event log of any local party gains an event (see <see cref="ILocalKeys.KeyEventAppended"/>),
    /// with its keys: <see cref="IPartyKeys.Party"/> and <see cref="ILocalKeys.State"/>. The transport pushes the new tail
    /// to the connected remotes of the party.
    /// </summary>
    public PerfectEvent<ILocalKeys> KeyEventAppended => _keyEventAppended.PerfectEvent;

    /// <summary>
    /// Publishes the encryption key of each local party in its description (see <see cref="ILocalKeys.GetEncryptionKey"/>).
    /// </summary>
    /// <param name="party">The local party.</param>
    /// <param name="builder">The description builder.</param>
    protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
    {
        if( party.GetFeature<LocalKeys>() is { } keys )
        {
            builder.EncryptionKey = keys.GetEncryptionKey( ApplicationIdentityService.SystemClock.UtcNow );
        }
    }

    // A new encryption key is published before the end of the current one: the description is contributed again.
    async Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount, System.Threading.CancellationToken cancel )
    {
        var utcNow = ApplicationIdentityService.SystemClock.UtcNow;
        var locals = ((IEnumerable<ILocalParty>)ApplicationIdentityService.TenantDomains).Prepend( ApplicationIdentityService );
        foreach( var local in locals )
        {
            if( local.GetFeature<LocalKeys>() is { } keys && keys.IsNewEncryptionKeyDue( utcNow, local.Description.EncryptionKey ) )
            {
                await OnDescriptionChangedAsync( monitor, local ).ConfigureAwait( false );
            }
        }
    }

    protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
    {
        ApplicationIdentityService.Heartbeat.Async += OnHeartbeatAsync;
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
        ApplicationIdentityService.Heartbeat.Async -= OnHeartbeatAsync;
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
            var localKeys = new LocalKeys.Builder( local, _protectorProvider, _keyStore, _alertRaised ).Build( context.Monitor );
            localKeys.KeyEventAppended.Async += ( monitor, state, cancel ) => _keyEventAppended.SafeRaiseAsync( monitor, localKeys, cancel );
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
        // IsDestroyed distinguishes "this party is gone" from "the application is shutting down":
        // the replay record must survive a restart, but not outlive the party it belongs to.
        r.GetFeature<RemoteKeys>()?.OnTeardown( context.Monitor, r.IsDestroyed );
    }

}
