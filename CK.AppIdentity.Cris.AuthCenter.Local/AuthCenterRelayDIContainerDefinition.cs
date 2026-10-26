using CK.Auth;
using CK.Core;
using CK.IO.AuthCenter;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The endpoint of the session commands relayed by a front (see <see cref="AuthCenterRelayHandler"/>): the session
/// endpoint is the relayed one, the authentication is read from the token presented to the front, the current local
/// party is the Authentication Center (the owner of the front) and the calling front is the <see cref="IRemoteParty"/>.
/// </summary>
[DIContainerDefinition( DIContainerKind.Endpoint )]
public abstract class AuthCenterRelayDIContainerDefinition : DIContainerDefinition<AuthCenterRelayDIContainerDefinition.Data>
{
    /// <summary>
    /// The scoped data of a relayed command.
    /// </summary>
    public sealed class Data : IScopedData
    {
        internal readonly IActivityMonitor _monitor;
        internal readonly IRemoteParty _caller;
        internal readonly AuthenticationInfo _authentication;
        // Null for a relayed ICommandAuthCenter: it is not a session command, it has no session endpoint.
        internal readonly RelayedEndpoint? _endpoint;

        internal Data( IActivityMonitor monitor, IRemoteParty caller, AuthenticationInfo authentication, RelayedEndpoint? endpoint )
        {
            _monitor = monitor;
            _caller = caller;
            _authentication = authentication;
            _endpoint = endpoint;
        }
    }

    /// <inheritdoc />
    public override void ConfigureContainerServices( IServiceCollection services,
                                                     Func<IServiceProvider, Data> scopeData,
                                                     IServiceProviderIsService globalServiceExists )
    {
        services.AddScoped( sp => scopeData( sp )._monitor );
        services.AddScoped( sp => scopeData( sp )._monitor.ParallelLogger );
        services.AddScoped( sp => scopeData( sp )._caller );
        services.AddScoped( sp => new CurrentLocalParty( scopeData( sp )._caller.Owner ) );
        services.AddScoped( sp => scopeData( sp )._authentication );
        services.AddScoped<IAuthenticationSessionEndpoint>( sp => scopeData( sp )._endpoint! );
    }
}

/// <summary>
/// The session endpoint of a relayed command: it presents what the front's endpoint presented, its secrets are the ones
/// the front prepared, and it records what the front's endpoint must apply.
/// </summary>
sealed class RelayedEndpoint : IAuthenticationSessionEndpoint
{
    readonly IRelaySessionCommand _command;

    public RelayedEndpoint( IRelaySessionCommand command ) => _command = command;

    public AuthenticationSessionProof? PresentedProof => _command.PresentedSessionKey == null
                                                            ? null
                                                            : new AuthenticationSessionProof( _command.PresentedSessionKey,
                                                                                              _command.PresentedRefreshSecretHash ?? string.Empty,
                                                                                              _command.PresentedBindingSecretHash ?? string.Empty );

    public string? PresentedToken => _command.Token;

    public (string RefreshSecretHash, string BindingSecretHash) PrepareSecrets() => (_command.NextRefreshSecretHash, _command.NextBindingSecretHash);

    public string? IssuedSessionKey { get; private set; }

    public bool RememberMe { get; private set; }

    public DateTime RefreshExpires { get; private set; }

    public bool Cleared { get; private set; }

    public AuthenticationSessionProof Issue( string sessionKey, bool rememberMe, DateTime refreshExpires )
    {
        IssuedSessionKey = sessionKey;
        RememberMe = rememberMe;
        RefreshExpires = refreshExpires;
        Cleared = false;
        return new AuthenticationSessionProof( sessionKey, _command.NextRefreshSecretHash, _command.NextBindingSecretHash );
    }

    public void Clear()
    {
        IssuedSessionKey = null;
        Cleared = true;
    }

    public string? RemoteLoginCallbackUrl => _command.RemoteLoginCallbackUrl;

    // The front's endpoint prepared it before relaying a starting remote login.
    public string PrepareRemoteLogin() => _command.RemoteLoginCorrelationHash
                                          ?? Throw.InvalidOperationException<string>( "The front did not prepare the remote login correlation." );

    public string? PresentedRemoteLoginHash => _command.PresentedRemoteLoginHash;

    public string? WebOrigin => _command.WebOrigin;
}
