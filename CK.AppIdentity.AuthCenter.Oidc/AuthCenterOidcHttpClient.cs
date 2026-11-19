using CK.Core;
using System;
using System.Net.Http;

namespace CK.AppIdentity.AuthCenter.Oidc;

/// <summary>
/// The HTTP client of the OpenID Connect scheme families: one connection pool, shared by the Authentication Centers of the
/// application (a removed tenant leaves no client behind), disposed with the services.
/// </summary>
public sealed class AuthCenterOidcHttpClient : ISingletonAutoService, IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="AuthCenterOidcHttpClient"/>.
    /// </summary>
    public AuthCenterOidcHttpClient()
    {
        Client = new HttpClient() { Timeout = TimeSpan.FromSeconds( 30 ) };
    }

    /// <summary>
    /// Gets the HTTP client.
    /// </summary>
    public HttpClient Client { get; }

    /// <inheritdoc />
    public void Dispose() => Client.Dispose();
}
