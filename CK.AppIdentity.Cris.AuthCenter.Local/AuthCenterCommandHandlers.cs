using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Handles the <see cref="IGetLoginSchemesQCommand"/> (the provider of a scheme family appears as the schemes of its
/// <see cref="IAuthCenterScheme"/>: "Oidc" as its configured "Oidc.&lt;Suffix&gt;" schemes). It is a singleton command:
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
    /// Handles the <see cref="IGetLoginSchemesQCommand"/>: the provider names of the login providers of the AuthCenter.
    /// </summary>
    [CommandHandler]
    public IList<string> Handle( IActivityMonitor monitor, IGetLoginSchemesQCommand command, CurrentLocalParty localParty )
    {
        var center = localParty.LocalParty.GetFeature<LocalAuthCenter>();
        var names = _providers.SelectMany( p => p.ProviderNames ).Distinct( StringComparer.OrdinalIgnoreCase ).ToList();
        // The provider of a scheme family is usable through the schemes of its family only.
        if( center != null )
        {
            foreach( var family in center.SchemeFamilies )
            {
                if( names.RemoveAll( n => string.Equals( n, family.ProviderName, StringComparison.OrdinalIgnoreCase ) ) > 0 )
                {
                    names.AddRange( family.Schemes );
                }
            }
        }
        return names.Order( StringComparer.OrdinalIgnoreCase ).ToList();
    }
}
