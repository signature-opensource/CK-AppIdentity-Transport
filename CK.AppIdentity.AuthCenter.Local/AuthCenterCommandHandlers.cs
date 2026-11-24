using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Handles the <see cref="IGetLoginSchemesQCommand"/>: the schemes of the enabled families of the AuthCenter
/// (<see cref="IAuthCenterScheme"/>: "Oidc" as its configured "Oidc.&lt;Suffix&gt;" schemes) whose provider is registered. It is a singleton command:
/// a party whose AuthCenter is remote dispatches it. The session commands are executed by their receiving endpoint
/// (CK.Cris.Authentication): their operations are handled by <see cref="AuthCenterOperationHandlers"/>.
/// </summary>
public sealed class AuthCenterCommandHandlers : ISingletonAutoService
{
    readonly IEnumerable<ILoginProvider> _providers;

    /// <summary>
    /// Initializes the handlers.
    /// </summary>
    /// <param name="providers">The login providers.</param>
    public AuthCenterCommandHandlers( IEnumerable<ILoginProvider> providers )
    {
        _providers = providers;
    }

    /// <summary>
    /// Handles the <see cref="IGetLoginSchemesQCommand"/>: the schemes of the enabled families of the AuthCenter whose login
    /// provider is registered (none without a local AuthCenter), with the lifetime of their Critical level (see <see cref="AuthCenterOptions.GetCriticalLifetime(string)"/>): zero for
    /// the <see cref="ActorInfo.WeakScheme"/>, whose actors are weak (at most <see cref="AuthLevel.Unsafe"/>).
    /// </summary>
    [CommandHandler]
    public IList<ILoginSchemeInfo> Handle( IActivityMonitor monitor, IGetLoginSchemesQCommand command, CurrentLocalParty localParty, PocoDirectory pocos )
    {
        var center = localParty.LocalParty.GetFeature<LocalAuthCenter>();
        if( center == null ) return [];
        // A scheme is available when an enabled family declares it and its provider is registered.
        var providers = _providers.SelectMany( p => p.ProviderNames ).ToHashSet( StringComparer.OrdinalIgnoreCase );
        var names = center.SchemeFamilies.Where( f => providers.Contains( f.ProviderName ) )
                                         .SelectMany( f => f.Schemes )
                                         .Distinct( StringComparer.OrdinalIgnoreCase );
        var options = center.Options;
        return names.Order( StringComparer.OrdinalIgnoreCase )
                    .Select( n => pocos.Create<ILoginSchemeInfo>( s =>
                    {
                        s.Name = n;
                        s.CriticalLifetime = string.Equals( n, ActorInfo.WeakScheme, StringComparison.OrdinalIgnoreCase )
                                                ? TimeSpan.Zero
                                                : options.GetCriticalLifetime( n );
                    } ) )
                    .ToList();
    }
}
