using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Tenants;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Tenants;

/// <summary>
/// Handles the tenant commands:
/// <list type="bullet">
///   <item>On the host of the operator's page, <see cref="IGetTenantHostsQCommand"/>: the hosts of its "Tenants" routes.</item>
///   <item>
///   On the application that holds the templates (the target of the party commands), <see cref="IGetTenantInstancesQCommand"/>,
///   <see cref="ICreateTenantInstanceCommand"/>, <see cref="ISetTenantIndexCommand"/> and <see cref="IRemoveTenantInstanceCommand"/>:
///   they call <see cref="IApplicationIdentityService"/>.
///   </item>
/// </list>
/// No right is checked but the Critical level: any user that reaches it can manage the tenants, unless the application
/// adds a validator. A change made while impersonating is refused: the operator acts as itself.
/// </summary>
public sealed class TenantHandlers : ISingletonAutoService
{
    /// <summary>
    /// Refuses a change made while impersonating.
    /// </summary>
    /// <param name="c">The message collector.</param>
    /// <param name="command">The command.</param>
    /// <param name="authentication">The authentication.</param>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, ICreateTenantInstanceCommand command, AuthenticationInfo authentication ) => RefuseImpersonation( c, authentication );

    /// <inheritdoc cref="Validate(UserMessageCollector, ICreateTenantInstanceCommand, AuthenticationInfo)"/>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, ISetTenantIndexCommand command, AuthenticationInfo authentication ) => RefuseImpersonation( c, authentication );

    /// <inheritdoc cref="Validate(UserMessageCollector, ICreateTenantInstanceCommand, AuthenticationInfo)"/>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IRemoveTenantInstanceCommand command, AuthenticationInfo authentication ) => RefuseImpersonation( c, authentication );

    static void RefuseImpersonation( UserMessageCollector c, AuthenticationInfo authentication )
    {
        if( authentication.IsImpersonated )
        {
            c.Error( "The tenants can't be changed while impersonating.", "AppIdentity.Tenants.Impersonated" );
        }
    }

    /// <summary>
    /// Lists the applications that hold tenant templates: the hosts of the "Tenants" routes of the local party.
    /// </summary>
    /// <param name="command">The query.</param>
    /// <param name="current">The local party (the host of the page).</param>
    /// <returns>The full names of the hosts.</returns>
    [CommandHandler]
    public IList<string> Handle( IGetTenantHostsQCommand command, CurrentLocalParty current )
    {
        var result = new List<string>();
        if( current.LocalParty is IApplicationIdentityService root && root.TenantTemplates.Count > 0 )
        {
            result.Add( root.FullName );
        }
        if( current.LocalParty.Description.Routes.TryGetValue( TenantsFeatureDriver.RouteName, out var routes ) )
        {
            result.AddRange( routes.Select( r => r.Host ) );
        }
        return result.Distinct( StringComparer.Ordinal ).Order( StringComparer.Ordinal ).ToList();
    }

    /// <summary>
    /// Lists the Opened tenant templates of the application and their instances.
    /// </summary>
    /// <param name="command">The query.</param>
    /// <param name="current">The target application.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The templates.</returns>
    [CommandHandler]
    public IList<ITenantTemplateInfo> Handle( IGetTenantInstancesQCommand command, CurrentLocalParty current, PocoDirectory pocos )
    {
        var result = new List<ITenantTemplateInfo>();
        if( current.LocalParty is not IApplicationIdentityService root ) return result;
        foreach( var t in root.TenantTemplates )
        {
            var info = pocos.Create<ITenantTemplateInfo>( i =>
            {
                i.TemplateName = t.DomainPrefix;
                i.ConfiguredCount = t.Instances.Count;
                i.MaxInstanceCount = t.Instances.MaxInstanceCount ?? t.Instances.Count;
            } );
            foreach( var d in root.TenantDomains.Where( d => d.Configuration.Template == t && !d.IsDestroyed )
                                                .OrderBy( d => d.Configuration.Instance!.Index ) )
            {
                info.Instances.Add( pocos.Create<ITenantInstanceInfo>( i =>
                {
                    i.Name = d.Configuration.Instance!.Name;
                    i.FullName = d.FullName;
                    i.Index = d.Configuration.Instance.Index;
                    i.IsConfigured = !d.Configuration.IsDynamicInstance;
                } ) );
            }
            foreach( var u in root.UnloadedTenants.Where( u => u.Template == t ).OrderBy( u => u.Name, StringComparer.OrdinalIgnoreCase ) )
            {
                info.Instances.Add( pocos.Create<ITenantInstanceInfo>( i =>
                {
                    i.Name = u.Name;
                    i.FullName = u.FullName;
                    i.Index = u.Index;
                    i.UnloadedReason = u.Reason.ToString();
                    i.UnloadedMessage = u.Message;
                } ) );
            }
            result.Add( info );
        }
        return result;
    }

    /// <summary>
    /// Creates a run-time tenant domain.
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The target application.</param>
    /// <param name="c">The message collector.</param>
    /// <returns>The full name of the new tenant domain, null on error.</returns>
    [CommandHandler]
    public async Task<string?> HandleAsync( IActivityMonitor monitor, ICreateTenantInstanceCommand command, CurrentLocalParty current, UserMessageCollector c )
    {
        if( !TryGetTemplate( current, command.TemplateName, c, out var root, out var template ) ) return null;
        var t = await root.AddTenantInstanceAsync( monitor, template, command.Name ).ConfigureAwait( false );
        if( t == null )
        {
            c.Error( $"Unable to create the tenant '{command.Name}' of '{command.TemplateName}' (see the logs of '{root.FullName}').", "AppIdentity.Tenants.CreateFailed" );
            return null;
        }
        return t.FullName;
    }

    /// <summary>
    /// Moves a run-time tenant domain to another free index.
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The target application.</param>
    /// <param name="c">The message collector.</param>
    /// <returns>True on success.</returns>
    [CommandHandler]
    public async Task<bool> HandleAsync( IActivityMonitor monitor, ISetTenantIndexCommand command, CurrentLocalParty current, UserMessageCollector c )
    {
        if( current.LocalParty is not IApplicationIdentityService root )
        {
            c.Error( $"'{current.LocalParty.FullName}' is not an application.", "AppIdentity.Tenants.NotAnApplication" );
            return false;
        }
        if( await root.SetTenantIndexAsync( monitor, command.TenantFullName, command.Index ).ConfigureAwait( false ) ) return true;
        c.Error( $"Unable to move '{command.TenantFullName}' to the index {command.Index} (see the logs of '{root.FullName}').", "AppIdentity.Tenants.MoveFailed" );
        return false;
    }

    /// <summary>
    /// Removes a run-time tenant domain.
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The target application.</param>
    /// <param name="c">The message collector.</param>
    /// <returns>True on success.</returns>
    [CommandHandler]
    public async Task<bool> HandleAsync( IActivityMonitor monitor, IRemoveTenantInstanceCommand command, CurrentLocalParty current, UserMessageCollector c )
    {
        if( current.LocalParty is not IApplicationIdentityService root )
        {
            c.Error( $"'{current.LocalParty.FullName}' is not an application.", "AppIdentity.Tenants.NotAnApplication" );
            return false;
        }
        if( await root.RemoveTenantInstanceAsync( monitor, command.TenantFullName ).ConfigureAwait( false ) ) return true;
        c.Error( $"Unable to remove '{command.TenantFullName}' (see the logs of '{root.FullName}').", "AppIdentity.Tenants.RemoveFailed" );
        return false;
    }

    static bool TryGetTemplate( CurrentLocalParty current,
                                string templateName,
                                UserMessageCollector c,
                                out IApplicationIdentityService root,
                                out TenantDomainTemplate template )
    {
        template = null!;
        if( current.LocalParty is not IApplicationIdentityService r )
        {
            root = null!;
            c.Error( $"'{current.LocalParty.FullName}' is not an application.", "AppIdentity.Tenants.NotAnApplication" );
            return false;
        }
        root = r;
        var t = r.TenantTemplates.FirstOrDefault( t => t.DomainPrefix.Equals( templateName, StringComparison.OrdinalIgnoreCase ) );
        if( t == null )
        {
            c.Error( $"'{r.FullName}' has no tenant template '{templateName}'.", "AppIdentity.Tenants.UnknownTemplate" );
            return false;
        }
        template = t;
        return true;
    }
}
