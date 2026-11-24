using CK.Core;
using System;

namespace CK.AppIdentity.AuthCenter.Passkey;

/// <summary>
/// The configuration of the "Passkey" option of the Authentication Center (its "AuthCenter:Passkey" section):
/// <code>
/// "AuthCenter": { "Passkey": { "RpId": "example.com", "RpName": "Example", "Timeout": "00:05:00" } }
/// </code>
/// Without <see cref="RpId"/>, the passkey family has no scheme.
/// </summary>
[ConfigurationModel]
public sealed class AuthCenterPasskeyOptionConfiguration : IConfigurationModel
{
    /// <summary>
    /// Gets the relying party identifier: a registrable domain (<c>example.com</c>), or <c>localhost</c> for the
    /// development. A passkey is bound to it: changing it orphans every registered passkey.
    /// </summary>
    public string? RpId { get; init; }

    /// <summary>
    /// Gets the relying party name shown by the authenticators. Defaults to the RpId.
    /// </summary>
    public string? RpName { get; init; }

    /// <summary>
    /// Gets the time given to the user to answer the authenticator: the lifetime of a ceremony (at most 10 minutes).
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes( 5 );

    /// <summary>
    /// Gets the normalized <see cref="RpId"/> (trimmed, lower case): a derived member, not a key.
    /// </summary>
    public string? NormalizedRpId => RpId?.Trim().ToLowerInvariant();

    /// <summary>
    /// Gets the effective relying party name: the <see cref="RpName"/>, otherwise the <see cref="NormalizedRpId"/>.
    /// </summary>
    public string? EffectiveRpName => RpName ?? NormalizedRpId;

    /// <inheritdoc />
    public void Validate( IConfigurationValidationContext context )
    {
        var rpId = NormalizedRpId;
        if( rpId != null && (rpId.Length == 0 || Uri.CheckHostName( rpId ) != UriHostNameType.Dns) )
        {
            context.Error( $"'{context.Path}:RpId' must be a domain name (\"example.com\" or \"localhost\"), without scheme nor port." );
        }
        if( rpId == null && RpName != null )
        {
            context.Error( $"'{context.Path}:RpName' is set but '{context.Path}:RpId' is missing: the passkeys are bound to a RpId." );
        }
        if( Timeout <= TimeSpan.Zero || Timeout > TimeSpan.FromMinutes( 10 ) )
        {
            context.Error( $"'{context.Path}:Timeout' = '{Timeout}': a positive time span of at most 10 minutes is expected." );
        }
    }
}
