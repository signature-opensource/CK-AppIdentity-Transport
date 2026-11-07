using CK.Core;
using System;
using System.Collections.Immutable;
using System.Linq;

namespace CK.AppIdentity.AuthCenter.Passkey;

/// <summary>
/// The settings of the passkeys of a local Authentication Center, read from its "AuthCenter:Passkey" section.
/// </summary>
public sealed class AuthCenterPasskeyOptions
{
    AuthCenterPasskeyOptions( string rpId, string rpName, TimeSpan timeout )
    {
        RpId = rpId;
        RpName = rpName;
        Timeout = timeout;
    }

    /// <summary>
    /// Gets the relying party identifier: a registrable domain ("example.com"), or "localhost" for the development.
    /// A passkey is bound to it: changing it orphans every registered passkey.
    /// </summary>
    public string RpId { get; }

    /// <summary>
    /// Gets the relying party name shown by the authenticators. Defaults to the <see cref="RpId"/>.
    /// </summary>
    public string RpName { get; }

    /// <summary>
    /// Gets the time given to the user to answer the authenticator: the lifetime of a ceremony. Defaults to 5 minutes.
    /// </summary>
    public TimeSpan Timeout { get; }

    /// <summary>
    /// Normalizes an origin: "scheme://host[:port]", lower case, without the default port. Null when it is not an
    /// absolute https URL (http on a loopback address) without path, query nor fragment.
    /// </summary>
    /// <param name="origin">The origin.</param>
    /// <returns>The normalized origin or null.</returns>
    public static string? NormalizeOrigin( string? origin )
    {
        if( !Uri.TryCreate( origin, UriKind.Absolute, out var u ) ) return null;
        if( u.Scheme != Uri.UriSchemeHttps && !(u.Scheme == Uri.UriSchemeHttp && u.IsLoopback) ) return null;
        if( u.AbsolutePath != "/" || u.Query.Length > 0 || u.Fragment.Length > 0 || u.UserInfo.Length > 0 ) return null;
        return u.GetLeftPart( UriPartial.Authority ).ToLowerInvariant();
    }

    /// <summary>
    /// Gets whether the origin of a passkey ceremony is accepted: it is the origin of the public URL of the party that
    /// relays the ceremony, the local party or one of its remotes (<see cref="PartyOrigins.IsCallerPartyUrl"/>: derived
    /// from what the parties state about themselves, never configured), https (http only on a loopback address), on the
    /// <see cref="RpId"/> or one of its sub-domains.
    /// </summary>
    /// <param name="local">The local party (the AuthCenter).</param>
    /// <param name="callerPartyId">The caller party identifier (<see cref="CK.Auth.AuthenticationInfo.CallerPartyId"/>).</param>
    /// <param name="origin">The origin of the endpoint that serves the ceremony.</param>
    /// <returns>True if the origin is accepted.</returns>
    public bool IsAllowedOrigin( ILocalParty local, int callerPartyId, string? origin )
    {
        if( NormalizeOrigin( origin ) is not string o ) return false;
        var host = new Uri( o ).Host;
        return (host == RpId || host.EndsWith( "." + RpId, StringComparison.Ordinal ))
               && PartyOrigins.IsCallerPartyUrl( local, callerPartyId, o );
    }

    internal static AuthCenterPasskeyOptions? Read( IActivityMonitor monitor, ImmutableConfigurationSection section )
    {
        bool success = true;
        void Error( string text )
        {
            monitor.Error( $"Invalid '{section.Path}': {text}" );
            success = false;
        }
        var rpId = section["RpId"]?.Trim().ToLowerInvariant();
        if( string.IsNullOrEmpty( rpId ) || Uri.CheckHostName( rpId ) != UriHostNameType.Dns )
        {
            Error( "'RpId' is required: a domain name (\"example.com\" or \"localhost\"), without scheme nor port." );
        }
        var rpName = section["RpName"] ?? rpId;
        var timeout = TimeSpan.FromMinutes( 5 );
        if( section["Timeout"] is string t && (!TimeSpan.TryParse( t, out timeout ) || timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes( 10 )) )
        {
            Error( $"'Timeout' = '{t}': a positive time span of at most 10 minutes is expected." );
        }
        return success ? new AuthCenterPasskeyOptions( rpId!, rpName!, timeout ) : null;
    }
}
