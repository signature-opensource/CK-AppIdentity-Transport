using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The front side of the relay: when the <see cref="CrisAuthCenter"/> of the <see cref="CurrentLocalParty"/> is remote,
/// the session commands are sent to it over the Cris channel (<see cref="IRelaySessionCommand"/>) and what it issues or
/// clears is applied to the <see cref="IAuthenticationSessionEndpoint"/>.
/// <para>
/// It fails closed: an unavailable or unreachable Authentication Center is an error, the command is never executed here.
/// The commands with sensitive data are refused until their fields are encrypted for the Authentication Center.
/// </para>
/// </summary>
public sealed class AuthCenterRelay : IAuthenticationSessionRelay
{
    /// <summary>
    /// The maximal time to wait for the remote Authentication Center: 30 seconds.
    /// </summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds( 30 );

    readonly CurrentLocalParty _localParty;
    readonly IAuthenticationSessionEndpoint _endpoint;
    readonly PocoDirectory _pocos;

    /// <summary>
    /// Initializes a new relay.
    /// </summary>
    /// <param name="localParty">The current local party.</param>
    /// <param name="endpoint">The endpoint that received the command.</param>
    /// <param name="pocos">The poco directory.</param>
    public AuthCenterRelay( CurrentLocalParty localParty, IAuthenticationSessionEndpoint endpoint, PocoDirectory pocos )
    {
        _localParty = localParty;
        _endpoint = endpoint;
        _pocos = pocos;
    }

    /// <inheritdoc />
    public Task<object?>? TryRelay( IActivityMonitor monitor, ICommandAuthenticationSession command )
    {
        Throw.CheckNotNullArgument( command );
        var center = _localParty.LocalParty.GetFeature<CrisAuthCenter>();
        if( center == null || center.IsLocal ) return null;
        return RelayAsync( monitor, center, command );
    }

    async Task<object?> RelayAsync( IActivityMonitor monitor, CrisAuthCenter center, ICommandAuthenticationSession command )
    {
        if( !center.IsAvailable )
        {
            return Failure( monitor, command, $"The AuthCenter '{center.AuthCenter}' of '{center.Owner}' is not available.", "Authentication.AuthCenterUnavailable" );
        }
        if( command.CrisPocoModel.HasSensitiveData )
        {
            return Failure( monitor, command, "A command with sensitive data cannot be relayed yet.", "Authentication.SensitiveRelayNotSupported" );
        }
        var channel = center.AuthCenter.GetFeature<CrisChannelFeature>();
        if( channel == null )
        {
            return Failure( monitor, command, $"The AuthCenter '{center.AuthCenter}' has no Cris channel.", "Authentication.AuthCenterUnreachable" );
        }
        var (nextRefresh, nextBinding) = _endpoint.PrepareSecrets();
        var presented = _endpoint.PresentedProof;
        var relayed = _pocos.Create<IRelaySessionCommand>( c =>
        {
            c.Command = command;
            c.Token = _endpoint.PresentedToken;
            c.PresentedSessionKey = presented?.SessionKey;
            c.PresentedRefreshSecretHash = presented?.RefreshSecretHash;
            c.PresentedBindingSecretHash = presented?.BindingSecretHash;
            c.NextRefreshSecretHash = nextRefresh;
            c.NextBindingSecretHash = nextBinding;
        } );
        IRelaySessionResult r;
        try
        {
            r = await channel.SendCommand( monitor, relayed ).WithResult<IRelaySessionResult>().Result.WaitAsync( Timeout ).ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Error( $"While relaying '{command.CrisPocoModel.PocoName}' to '{center.AuthCenter}'.", ex );
            return Failure( monitor, command, $"The AuthCenter '{center.AuthCenter}' cannot be reached.", "Authentication.AuthCenterUnreachable" );
        }
        if( r.Cleared ) _endpoint.Clear();
        if( r.IssuedSessionKey != null )
        {
            var issued = _endpoint.Issue( r.IssuedSessionKey, r.RememberMe, r.RefreshExpires );
            if( issued.RefreshSecretHash != nextRefresh || issued.BindingSecretHash != nextBinding )
            {
                // The endpoint doesn't honor PrepareSecrets: its secrets are not the ones the AuthCenter stored.
                _endpoint.Clear();
                Throw.InvalidOperationException( "The endpoint did not issue the prepared secrets." );
            }
        }
        return r.Result;
    }

    // A failure of a command that has no result (logout) is a null result: the endpoint secrets are cleared anyway.
    object? Failure( IActivityMonitor monitor, ICommandAuthenticationSession command, string text, string resName )
    {
        if( command is ICommand<ISessionResult> c ) return AuthCenterResults.Failure( monitor, c, text, resName );
        monitor.Warn( $"Session command '{command.CrisPocoModel.PocoName}' not relayed: {text}" );
        if( command is ILogoutSessionCommand ) _endpoint.Clear();
        return null;
    }
}
