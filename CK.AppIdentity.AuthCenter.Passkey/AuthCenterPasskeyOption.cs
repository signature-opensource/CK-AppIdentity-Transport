using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AppIdentity.AuthCenter.Passkey;

/// <summary>
/// The "Passkey" option of the Authentication Center: the passkey scheme family (<see cref="AuthCenterPasskey"/>) of every
/// local Authentication Center, the dynamic tenants included, with the settings of its "AuthCenter:Passkey" section
/// (its configuration model is <see cref="AuthCenterPasskeyOptionConfiguration"/>; without a RpId the family has no scheme).
/// The passkeys are available only with an <see cref="IPasskeyStore"/>.
/// </summary>
[PartyFeatureOption( "Passkey", TypeActivation.ByDefault )]
[Configuration<AuthCenterPasskeyOptionConfiguration>]
public sealed class AuthCenterPasskeyOption : IPartyComponentOption<LocalAuthCenterFeatureDriver>, IAuthCenterSchemeFamilyOption
{
    readonly bool _hasStore;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterPasskeyOption"/>.
    /// </summary>
    /// <param name="configuration">The configuration, read (key by key along the levels of the party) and validated.</param>
    /// <param name="services">The services: the passkeys are available only with an <see cref="IPasskeyStore"/>.</param>
    public AuthCenterPasskeyOption( AuthCenterPasskeyOptionConfiguration configuration, IServiceProvider services )
    {
        Throw.CheckNotNullArgument( configuration );
        _hasStore = services.GetService<IPasskeyStore>() != null;
        Settings = configuration.NormalizedRpId != null ? AuthCenterPasskeyOptions.From( configuration ) : null;
    }

    /// <summary>
    /// Gets the settings. Null when no RpId is configured.
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
