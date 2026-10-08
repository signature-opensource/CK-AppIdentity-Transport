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
/// The [Sensitive] strings of a command are encrypted in place for the Authentication Center (see <see cref="AuthCenterFieldEncryption"/>).
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
        var channel = center.AuthCenter.GetFeature<CrisChannelFeature>();
        if( channel == null )
        {
            return Failure( monitor, command, $"The AuthCenter '{center.AuthCenter}' has no Cris channel.", "Authentication.AuthCenterUnreachable" );
        }
        if( command.CrisPocoModel.HasSensitiveData && !await EncryptSensitiveFieldsAsync( monitor, center, channel, command ).ConfigureAwait( false ) )
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
    async ValueTask<bool> EncryptSensitiveFieldsAsync( IActivityMonitor monitor, CrisAuthCenter center, CrisChannelFeature channel, ICommandAuthenticationSession command )
    {
        var fields = AuthCenterFieldEncryption.GetSensitiveFields( command.GetType() );
        if( fields == null )
        {
            monitor.Warn( $"'{command.CrisPocoModel.PocoName}' has sensitive data that is not a string: it cannot be encrypted." );
            return false;
        }
        var key = await center.GetEncryptionKeyAsync( monitor, channel, _pocos ).ConfigureAwait( false );
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

    // A failure of a command that has no result (logout) is a null result: the endpoint secrets are cleared anyway.
    // A command with another result (the RedirectedUrl of a start login) fails with an error.
    object? Failure( IActivityMonitor monitor, ICommandAuthenticationSession command, string text, string resName )
    {
        if( command is ICommand<ISessionResult> c ) return AuthCenterResults.Failure( monitor, c, text, resName );
        monitor.Warn( $"Session command '{command.CrisPocoModel.PocoName}' not relayed: {text}" );
        if( command is ILogoutSessionCommand )
        {
            _endpoint.Clear();
            return null;
        }
        return _pocos.Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) ) );
    }
}
