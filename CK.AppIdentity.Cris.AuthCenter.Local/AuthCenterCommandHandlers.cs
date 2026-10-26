using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Handles the session commands that are not logins (refresh, logout, impersonation) with the
/// <see cref="AuthCenterSessionService"/>, and the <see cref="IGetLoginSchemesQCommand"/> (the provider of a scheme family
/// appears as the schemes of its <see cref="IAuthCenterScheme"/>: "Oidc" as its configured "Oidc.&lt;Suffix&gt;" schemes).
/// The logins are handled by the packages that implement the authentication providers (except, temporarily, the Basic
/// and Weak ones: see <see cref="AuthCenterBasicLoginHandler"/> and <see cref="AuthCenterWeakLoginHandler"/>).
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
    /// Handles the <see cref="IRefreshSessionCommand"/>.
    /// </summary>
    [CommandHandler]
    public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, IRefreshSessionCommand command, AuthCenterSessionService sessions )
        => sessions.RefreshAsync( monitor, command );

    /// <summary>
    /// Handles the <see cref="ILogoutSessionCommand"/>.
    /// </summary>
    [CommandHandler]
    public async Task HandleAsync( IActivityMonitor monitor, ILogoutSessionCommand command, AuthCenterSessionService sessions )
        => await sessions.LogoutAsync( monitor ).ConfigureAwait( false );

    /// <summary>
    /// Handles the <see cref="IImpersonateCommand"/>.
    /// </summary>
    [CommandHandler]
    public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, IImpersonateCommand command, AuthCenterSessionService sessions )
        => sessions.ImpersonateAsync( monitor, command );

    /// <summary>
    /// Handles the <see cref="IClearImpersonationCommand"/>.
    /// </summary>
    [CommandHandler]
    public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, IClearImpersonationCommand command, AuthCenterSessionService sessions )
        => sessions.ClearImpersonationAsync( monitor, command );

    /// <summary>
    /// Handles the <see cref="IGetLoginSchemesQCommand"/>: the provider names of the login providers of the AuthCenter.
    /// It is an <c>ICommandAuthCenter</c>: a front's endpoint relays it to its remote AuthCenter.
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
