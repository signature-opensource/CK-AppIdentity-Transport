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
/// <see cref="AuthCenterSessionService"/>, and the <see cref="IGetLoginSchemesQCommand"/> (the "Oidc" provider appears as its
/// configured "Oidc.&lt;Suffix&gt;" schemes).
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
    /// A front asks its remote AuthCenter (it may have no providers at all).
    /// </summary>
    [CommandHandler]
    public async Task<IList<string>> HandleAsync( IActivityMonitor monitor, IGetLoginSchemesQCommand command, CurrentLocalParty localParty )
    {
        var center = localParty.LocalParty.GetFeature<CrisAuthCenter>();
        if( center != null && !center.IsLocal )
        {
            var channel = center.AuthCenter.GetFeature<CrisChannelFeature>();
            if( !center.IsAvailable || channel == null ) return [];
            return await channel.SendCommand( monitor, command ).WithResult<IList<string>>().Result.WaitAsync( AuthCenterRelay.Timeout ).ConfigureAwait( false );
        }
        var names = _providers.SelectMany( p => p.ProviderNames ).Distinct( StringComparer.OrdinalIgnoreCase ).ToList();
        // The "Oidc" provider is usable through its configured schemes only.
        if( names.RemoveAll( n => string.Equals( n, "Oidc", StringComparison.OrdinalIgnoreCase ) ) > 0 && center?.Local != null )
        {
            names.AddRange( center.Local.Options.OidcSchemes.Select( o => o.Scheme ) );
        }
        return names.Order( StringComparer.OrdinalIgnoreCase ).ToList();
    }
}
