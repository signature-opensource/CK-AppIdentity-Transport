using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The front side of the relay: the session commands are sent to the remote Authentication Center of the
/// <see cref="CurrentLocalParty"/> (its <see cref="RemoteAuthCenter"/>) over the Cris channel (<see cref="IRelaySessionCommand"/>)
/// and what it issues or clears is applied to the <see cref="IAuthenticationSessionEndpoint"/>.
/// <para>
/// It fails closed: a missing, unavailable or unreachable Authentication Center is an error, the command is never
/// executed here.
/// The [Sensitive] strings of a command are encrypted in place for the Authentication Center (see <see cref="AuthCenterFieldEncryption"/>).
/// </para>
/// <para>
/// It also relays the commands executed by the Authentication Center (<see cref="ICommandAuthCenter"/>) with
/// <see cref="IRelayAuthCenterCommand"/>: the caller's token and the hash of its binding secret travel with them, the
/// Authentication Center establishes the identity again.
/// </para>
/// </summary>
public sealed class AuthCenterRelay : IAuthenticationSessionRelay, IAuthCenterCommandRelay
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
    public Task<object?> RelayAsync( IActivityMonitor monitor, ICommandAuthenticationSession command )
    {
        Throw.CheckNotNullArgument( command );
        var remote = _localParty.LocalParty.GetFeature<RemoteAuthCenter>();
        if( remote == null )
        {
            return Task.FromResult( Failure( monitor, command, $"'{_localParty.LocalParty}' has no AuthCenter.", "Authentication.NoAuthCenter" ) );
        }
        return RelayAsync( monitor, remote, command );
    }

    /// <inheritdoc />
    public Task<object?> RelayAsync( IActivityMonitor monitor, ICommandAuthCenter command )
    {
        Throw.CheckNotNullArgument( command );
        var remote = _localParty.LocalParty.GetFeature<RemoteAuthCenter>();
        if( remote == null )
        {
            return Task.FromResult<object?>( Error( monitor, command, $"'{_localParty.LocalParty}' has no AuthCenter.", "Authentication.NoAuthCenter" ) );
        }
        return RelayAuthCenterCommandAsync( monitor, remote, command );
    }

    async Task<object?> RelayAuthCenterCommandAsync( IActivityMonitor monitor, RemoteAuthCenter remote, ICommandAuthCenter command )
    {
        var center = remote.Center;
        if( command is ICommandAuthenticationSession )
        {
            // A setup error (two routes): never relayed without its session secrets.
            return Error( monitor, command, "A session command is relayed as a session command.", "Authentication.InvalidCommand" );
        }
        if( !center.IsAvailable )
        {
            return Error( monitor, command, $"The AuthCenter '{center.AuthCenter}' of '{center.Owner}' is not available.", "Authentication.AuthCenterUnavailable" );
        }
        var channel = center.AuthCenter.GetFeature<CrisChannelFeature>();
        if( channel == null )
        {
            return Error( monitor, command, $"The AuthCenter '{center.AuthCenter}' has no Cris channel.", "Authentication.AuthCenterUnreachable" );
        }
        if( command.CrisPocoModel.HasSensitiveData && !await EncryptSensitiveFieldsAsync( monitor, remote, channel, command ).ConfigureAwait( false ) )
        {
            return Error( monitor, command, $"The sensitive fields cannot be encrypted for the AuthCenter '{center.AuthCenter}'.", "Authentication.SensitiveEncryptionFailed" );
        }
        var relayed = _pocos.Create<IRelayAuthCenterCommand>( c =>
        {
            c.Command = (IAbstractCommand)command;
            c.Token = _endpoint.PresentedToken;
            c.PresentedBindingSecretHash = _endpoint.PresentedBindingSecretHash;
        } );
        try
        {
            var r = await channel.SendCommand( monitor, relayed ).WithResult<IRelayAuthCenterResult>().Result.WaitAsync( Timeout ).ConfigureAwait( false );
            return r.Result;
        }
        catch( Exception ex )
        {
            monitor.Error( $"While relaying '{command.CrisPocoModel.PocoName}' to '{center.AuthCenter}'.", ex );
            return Error( monitor, command, $"The AuthCenter '{center.AuthCenter}' cannot be reached.", "Authentication.AuthCenterUnreachable" );
        }
    }

    object Error( IActivityMonitor monitor, ICrisPoco command, string text, string resName )
    {
        monitor.Warn( $"'{command.CrisPocoModel.PocoName}' not relayed: {text}" );
        return _pocos.Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) ) );
    }

    async Task<object?> RelayAsync( IActivityMonitor monitor, RemoteAuthCenter remote, ICommandAuthenticationSession command )
    {
        var center = remote.Center;
        if( !center.IsAvailable )
        {
            return Failure( monitor, command, $"The AuthCenter '{center.AuthCenter}' of '{center.Owner}' is not available.", "Authentication.AuthCenterUnavailable" );
        }
        var channel = center.AuthCenter.GetFeature<CrisChannelFeature>();
        if( channel == null )
        {
            return Failure( monitor, command, $"The AuthCenter '{center.AuthCenter}' has no Cris channel.", "Authentication.AuthCenterUnreachable" );
        }
        if( command.CrisPocoModel.HasSensitiveData && !await EncryptSensitiveFieldsAsync( monitor, remote, channel, command ).ConfigureAwait( false ) )
        {
            return Failure( monitor, command, $"The sensitive fields cannot be encrypted for the AuthCenter '{center.AuthCenter}'.", "Authentication.SensitiveEncryptionFailed" );
        }
        var (nextRefresh, nextBinding) = _endpoint.PrepareSecrets();
        var presented = _endpoint.PresentedProof;
        var callbackUrl = _endpoint.RemoteLoginCallbackUrl;
        var correlation = command is IStartLoginCommand && callbackUrl != null ? _endpoint.PrepareRemoteLogin() : null;
        var relayed = _pocos.Create<IRelaySessionCommand>( c =>
        {
            c.Command = command;
            c.Token = _endpoint.PresentedToken;
            c.PresentedSessionKey = presented?.SessionKey;
            c.PresentedRefreshSecretHash = presented?.RefreshSecretHash;
            c.PresentedBindingSecretHash = presented?.BindingSecretHash;
            c.NextRefreshSecretHash = nextRefresh;
            c.NextBindingSecretHash = nextBinding;
            c.RemoteLoginCallbackUrl = callbackUrl;
            c.RemoteLoginCorrelationHash = correlation;
            c.PresentedRemoteLoginHash = _endpoint.PresentedRemoteLoginHash;
            c.WebOrigin = _endpoint.WebOrigin;
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

    // Replaces every [Sensitive] string of the command by its ciphertext for the AuthCenter. The command is consumed by the
    // relay: its clear values are not restored (it may still be queued for sending when the relay gives up).
    async ValueTask<bool> EncryptSensitiveFieldsAsync( IActivityMonitor monitor, RemoteAuthCenter remote, CrisChannelFeature channel, ICrisPoco command )
    {
        var center = remote.Center;
        var fields = AuthCenterFieldEncryption.GetSensitiveFields( command.GetType() );
        if( fields == null )
        {
            monitor.Warn( $"'{command.CrisPocoModel.PocoName}' has sensitive data that is not a string: it cannot be encrypted." );
            return false;
        }
        var key = await remote.GetEncryptionKeyAsync( monitor, channel, _pocos ).ConfigureAwait( false );
        if( key == null ) return false;
        var utcNow = DateTime.UtcNow;
        foreach( var f in fields )
        {
            if( f.GetValue( command ) is string clear )
            {
                var context = AuthCenterFieldEncryption.GetContext( center.AuthCenter.FullName, center.Owner.FullName, command.CrisPocoModel.PocoName, f.Name );
                f.SetValue( command, AuthCenterFieldEncryption.Encrypt( key, clear, context, utcNow ) );
            }
        }
        return true;
    }

    // The relay failed: nothing has been decided (the AuthCenter is missing, unavailable or unreachable). This is an error result,
    // never a failed ISessionResult (that is a decision of the AuthCenter: a client ends its session on a failed refresh,
    // and retries on an error). A failure of a command that has no result (logout) is a null result: the endpoint secrets
    // are cleared anyway.
    object? Failure( IActivityMonitor monitor, ICommandAuthenticationSession command, string text, string resName )
    {
        monitor.Warn( $"Session command '{command.CrisPocoModel.PocoName}' not relayed: {text}" );
        if( command is ILogoutSessionCommand )
        {
            _endpoint.Clear();
            return null;
        }
        return _pocos.Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) ) );
    }
}
