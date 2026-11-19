using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AppIdentity.AuthCenter.Passkey;

/// <summary>
/// The "Passkey" option of the Authentication Center: the passkey scheme family (<see cref="AuthCenterPasskey"/>) of every
/// local Authentication Center, the dynamic tenants included, with the settings of its "AuthCenter:Passkey" section
/// (<see cref="AuthCenterPasskeyOptions"/>; possibly absent: the family then has no scheme). The passkeys are available
/// only with an <see cref="IPasskeyStore"/>.
/// </summary>
[PartyFeatureOption( "Passkey", TypeActivation.ByDefault )]
public sealed class AuthCenterPasskeyOption : IPartyComponentOption<LocalAuthCenterFeatureDriver>, IAuthCenterSchemeFamilyOption
{
    readonly bool _hasStore;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterPasskeyOption"/>.
    /// </summary>
    /// <param name="configuration">The "AuthCenter:Passkey" section. Null when there is none.</param>
    /// <param name="services">The services: the passkeys are available only with an <see cref="IPasskeyStore"/>.</param>
    public AuthCenterPasskeyOption( IConfiguration? configuration, IServiceProvider services )
    {
        _hasStore = services.GetService<IPasskeyStore>() != null;
        Settings = configuration != null ? AuthCenterPasskeyOptions.Read( configuration ) : null;
    }

    /// <summary>
    /// Gets the settings. Null when the "AuthCenter:Passkey" section is not configured.
    /// </summary>
    public AuthCenterPasskeyOptions? Settings { get; }

    /// <inheritdoc />
    public IAuthCenterScheme CreateFamily( IActivityMonitor monitor, ILocalParty local )
    {
        if( Settings != null && !_hasStore )
        {
            monitor.Warn( $"The passkeys of '{local}' are configured but there is no IPasskeyStore: they are not available." );
        }
        return new AuthCenterPasskey( Settings, _hasStore, local.ApplicationIdentityService.SystemClock );
    }
}
