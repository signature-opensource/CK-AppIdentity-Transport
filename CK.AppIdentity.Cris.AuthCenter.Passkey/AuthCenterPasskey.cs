using CK.Core;
using Fido2NetLib;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.Cris.AuthCenter.Passkey;

/// <summary>
/// The passkey (WebAuthn) scheme family of a <see cref="LocalAuthCenter"/>: the "Passkey" scheme, verified here with
/// Fido2NetLib. It keeps the pending ceremonies (a login or a registration that waits for the browser's response).
/// <para>
/// The "Passkey" scheme is available when the "AuthCenter:Passkey" section configures it and an <see cref="IPasskeyStore"/>
/// is registered. Without them, the family exists but has no scheme: it hides the "Passkey" provider name.
/// </para>
/// </summary>
public sealed class AuthCenterPasskey : IAuthCenterScheme
{
    /// <summary>
    /// The maximal number of pending ceremonies: 10,000. Starting a login is anonymous: this bounds the memory.
    /// </summary>
    public const int MaxPendingCeremonies = 10_000;

    readonly AuthCenterPasskeyOptions? _options;
    readonly bool _hasStore;
    readonly AuthCenterPendingStore<PasskeyCeremony>? _ceremonies;

    internal AuthCenterPasskey( AuthCenterPasskeyOptions? options, bool hasStore )
    {
        _options = options;
        _hasStore = hasStore;
        if( options != null && hasStore )
        {
            _ceremonies = new AuthCenterPendingStore<PasskeyCeremony>( options.Timeout, MaxPendingCeremonies );
        }
    }

    /// <summary>
    /// Gets the options. Null when the "AuthCenter:Passkey" section is not configured.
    /// </summary>
    public AuthCenterPasskeyOptions? Options => _options;

    /// <summary>
    /// Gets whether the "Passkey" scheme is available: configured, with an <see cref="IPasskeyStore"/>.
    /// </summary>
    public bool IsAvailable => _ceremonies != null;

    /// <summary>
    /// Gets the pending ceremonies, under their challenge. Null when the scheme is not <see cref="IsAvailable"/>.
    /// </summary>
    public AuthCenterPendingStore<PasskeyCeremony>? Ceremonies => _ceremonies;

    /// <inheritdoc />
    public string ProviderName => PasskeyLoginPayload.Scheme;

    /// <inheritdoc />
    public IEnumerable<string> Schemes => IsAvailable ? [PasskeyLoginPayload.Scheme] : [];

    /// <inheritdoc />
    public bool AllowsAccountCreation( string scheme ) => false;

    /// <summary>
    /// Creates the Fido2NetLib verifier for a ceremony of an origin: the relying party of the options, and this origin
    /// only (the signed origin must be the one of the endpoint that serves the ceremony).
    /// </summary>
    /// <param name="origin">The normalized origin of the endpoint.</param>
    /// <returns>The verifier.</returns>
    internal Fido2 CreateFido2( string origin )
    {
        Throw.DebugAssert( _options != null );
        return new Fido2( new Fido2Configuration
        {
            RPID = _options.RpId,
            RPName = _options.RpName,
            Origins = new HashSet<string>( [origin], StringComparer.Ordinal ),
            Timeout = (uint)_options.Timeout.TotalMilliseconds
        }, null! );
    }
}

/// <summary>
/// A pending passkey ceremony: a login or a registration that waits for the browser's response.
/// </summary>
/// <param name="IsRegistration">True for a registration, false for a login.</param>
/// <param name="Origin">The normalized origin of the endpoint that started it.</param>
/// <param name="OptionsJson">The options sent to the browser (they are verified against the response).</param>
/// <param name="SessionKey">The session that started a registration (null for a login).</param>
/// <param name="ActorId">The actor of a registration (0 for a login).</param>
/// <param name="Name">The name of the registered passkey (empty for a login).</param>
public sealed record PasskeyCeremony( bool IsRegistration, string Origin, string OptionsJson, string? SessionKey, int ActorId, string Name );
