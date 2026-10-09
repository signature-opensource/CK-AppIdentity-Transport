using CK.Core;
using System;
using System.Collections.Immutable;
using System.Linq;

namespace CK.AppIdentity.Cris.AuthCenter.Passkey;

/// <summary>
/// The settings of the passkeys of a local Authentication Center, read from its "AuthCenter:Passkey" section.
/// </summary>
public sealed class AuthCenterPasskeyOptions
{
    AuthCenterPasskeyOptions( string rpId, string rpName, ImmutableArray<string> origins, TimeSpan timeout )
    {
        RpId = rpId;
        RpName = rpName;
        Origins = origins;
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
    /// Gets the accepted origins ("https://app.example.com"): the <see cref="RpId"/> or one of its sub-domains, https
    /// (http only on a loopback address). A passkey ceremony is accepted only from an endpoint whose origin is one of them.
    /// </summary>
    public ImmutableArray<string> Origins { get; }

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
    /// Gets whether an origin (normalized or not) is one of the <see cref="Origins"/>.
    /// </summary>
    /// <param name="origin">The origin.</param>
    /// <returns>True if the origin is accepted.</returns>
    public bool IsAllowedOrigin( string? origin ) => NormalizeOrigin( origin ) is string o && Origins.Contains( o, StringComparer.Ordinal );

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
        var origins = ImmutableArray.CreateBuilder<string>();
        var o = section.TryGetSection( "Origins" );
        var values = o == null
                        ? []
                        : o.HasChildren
                            ? o.GetChildren().Select( c => c.Value ).ToArray()
                            : (o.Value ?? "").Split( ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries );
        foreach( var v in values )
        {
            var n = NormalizeOrigin( v );
            if( n == null )
            {
                Error( $"origin '{v}' must be an absolute https URL (http only on a loopback address) without path." );
            }
            else if( rpId != null )
            {
                var host = new Uri( n ).Host;
                if( host != rpId && !host.EndsWith( "." + rpId, StringComparison.Ordinal ) )
                {
                    Error( $"origin '{v}' is not on the RpId '{rpId}' (nor one of its sub-domains)." );
                }
                else origins.Add( n );
            }
        }
        if( origins.Count == 0 && success ) Error( "'Origins' is required (the origins of the endpoints that serve the passkey ceremonies)." );
        var timeout = TimeSpan.FromMinutes( 5 );
        if( section["Timeout"] is string t && (!TimeSpan.TryParse( t, out timeout ) || timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes( 10 )) )
        {
            Error( $"'Timeout' = '{t}': a positive time span of at most 10 minutes is expected." );
        }
        return success ? new AuthCenterPasskeyOptions( rpId!, rpName!, origins.ToImmutable(), timeout ) : null;
    }
}
