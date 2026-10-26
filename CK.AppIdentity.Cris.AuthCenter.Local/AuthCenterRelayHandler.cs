using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The Authentication Center side of the relay: executes the session commands and the <see cref="ICommandAuthCenter"/>
/// commands relayed by its fronts.
/// <para>
/// Only a remote of the Authentication Center that has its "AuthCenter" feature (it is a front of this Authentication
/// Center) can relay. The relayed command is validated as an incoming command and executed in the
/// <see cref="AuthCenterRelayDIContainerDefinition"/> endpoint. The token presented to the front is read again here: the
/// front is never trusted. The [Sensitive] strings must be encrypted for this Authentication Center: they are decrypted
/// before the validation, a clear value is refused.
/// </para>
/// </summary>
public sealed class AuthCenterRelayHandler : ISingletonAutoService
{
    readonly IDIContainer<AuthCenterRelayDIContainerDefinition.Data> _container;

    /// <summary>
    /// Initializes the relay handler.
    /// </summary>
    /// <param name="container">The relay endpoint.</param>
    public AuthCenterRelayHandler( IDIContainer<AuthCenterRelayDIContainerDefinition.Data> container )
    {
        _container = container;
    }

    /// <summary>
    /// Handles a <see cref="IRelaySessionCommand"/> sent by a front.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The relay command.</param>
    /// <param name="caller">The front that sent it.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The relay result.</returns>
    [CommandHandler]
    public async Task<IRelaySessionResult> HandleAsync( IActivityMonitor monitor, IRelaySessionCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var inner = command.Command as ICommandAuthenticationSession;
        if( inner == null )
        {
            monitor.Warn( $"'{caller}' relayed a command that is not a session command." );
            return pocos.Create<IRelaySessionResult>();
        }
        var center = GetLocal( caller );
        if( center == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' is not a front of an AuthCenter here: its relayed '{inner.CrisPocoModel.PocoName}' is refused." );
            return Result( pocos, Failure( monitor, pocos, inner, "Not a front of this AuthCenter.", "Authentication.RelayNotAllowed" ) );
        }
        if( inner.CrisPocoModel.HasSensitiveData && !DecryptSensitiveFields( monitor, center, caller, inner ) )
        {
            return Result( pocos, Failure( monitor, pocos, inner, "The sensitive fields must be encrypted for the AuthCenter.", "Authentication.SensitiveNotEncrypted" ) );
        }
        var authentication = AuthenticationInfo.None;
        if( command.Token != null && await center.Center.ReadTokenAsync( monitor, command.Token, DateTime.UtcNow ).ConfigureAwait( false ) is { } read )
        {
            authentication = read.Info;
        }
        var endpoint = new RelayedEndpoint( command );
        await using var scope = _container.GetContainer().CreateAsyncScope( new AuthCenterRelayDIContainerDefinition.Data( monitor, caller, authentication, endpoint ) );
        var services = scope.ServiceProvider;
        object? result;
        var validation = await services.GetRequiredService<RawCrisReceiver>().IncomingValidateAsync( monitor, services, inner ).ConfigureAwait( false );
        if( !validation.Success )
        {
            var text = validation.ValidationMessages.Where( m => m.Level == UserMessageLevel.Error ).Select( m => m.Text ).FirstOrDefault() ?? "Invalid command.";
            result = Failure( monitor, pocos, inner, text, "Authentication.InvalidRelayedCommand" );
        }
        else
        {
            result = (await services.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( services, inner ).ConfigureAwait( false )).Result;
        }
        return pocos.Create<IRelaySessionResult>( r =>
        {
            r.Result = result;
            r.IssuedSessionKey = endpoint.IssuedSessionKey;
            r.RememberMe = endpoint.RememberMe;
            r.RefreshExpires = endpoint.RefreshExpires;
            r.Cleared = endpoint.Cleared;
        } );
    }

    /// <summary>
    /// Handles the <see cref="IGetAuthCenterEncryptionKeyQCommand"/> of a front: the current encryption key, signed.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="caller">The front that sent it.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The signed public key.</returns>
    /// <summary>
    /// Handles a command executed by the Authentication Center that a front relays (<see cref="IRelayAuthCenterCommand"/>).
    /// Only the <see cref="ICommandAuthCenter"/> commands are accepted (never a session command: they have their own
    /// relay), from a front of this Authentication Center. The identity is established again from the caller's proof
    /// (see <see cref="AuthenticateAsync"/>), then the command is validated and executed.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The relay command.</param>
    /// <param name="caller">The front.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The result of the relayed command.</returns>
    [CommandHandler]
    public async Task<IRelayAuthCenterResult> HandleAsync( IActivityMonitor monitor, IRelayAuthCenterCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var center = GetLocal( caller );
        if( center == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' is not a front of an AuthCenter here: its relayed '{command.Command?.CrisPocoModel.PocoName}' is refused." );
            return Relayed( pocos, Error( pocos, "Not a front of this AuthCenter.", "Authentication.RelayNotAllowed" ) );
        }
        var inner = command.Command;
        if( inner is not ICommandAuthCenter || inner is ICommandAuthenticationSession )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' relayed '{inner?.CrisPocoModel.PocoName}': only the ICommandAuthCenter commands are executed for a front." );
            return Relayed( pocos, Error( pocos, "This command is not executed by the AuthCenter.", "Authentication.RelayNotAllowed" ) );
        }
        if( inner.CrisPocoModel.HasSensitiveData && !DecryptSensitiveFields( monitor, center, caller, inner ) )
        {
            return Relayed( pocos, Error( pocos, "The sensitive fields must be encrypted for the AuthCenter.", "Authentication.SensitiveNotEncrypted" ) );
        }
        var authentication = await AuthenticateAsync( monitor, center, command ).ConfigureAwait( false );
        await using var scope = _container.GetContainer().CreateAsyncScope( new AuthCenterRelayDIContainerDefinition.Data( monitor, caller, authentication, null ) );
        var services = scope.ServiceProvider;
        var validation = await services.GetRequiredService<RawCrisReceiver>().IncomingValidateAsync( monitor, services, inner ).ConfigureAwait( false );
        if( !validation.Success )
        {
            var errors = validation.ValidationMessages.Where( m => m.Level == UserMessageLevel.Error ).ToList();
            if( errors.Count == 0 ) errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, "Invalid command.", "Authentication.InvalidRelayedCommand" ) );
            return Relayed( pocos, pocos.Create<ICrisResultError>( e => { foreach( var m in errors ) e.Errors.Add( m ); } ) );
        }
        var executed = await services.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( services, inner ).ConfigureAwait( false );
        return Relayed( pocos, executed.Result );
    }

    /// <summary>
    /// Establishes the identity of a relayed <see cref="ICommandAuthCenter"/> from the caller's proof, never from the
    /// front: a token of this Authentication Center, presented with the binding secret of its session, whose session is
    /// alive and is still the token's one (same binding and same actor: a refresh rotates the binding, a logout or a
    /// revocation deletes the session, an impersonation changes the actor). Anything else is the anonymous: the
    /// authentication parts of the command then fail its validation.
    /// </summary>
    static async ValueTask<AuthenticationInfo> AuthenticateAsync( IActivityMonitor monitor, LocalAuthCenter center, IRelayAuthCenterCommand command )
    {
        if( command.Token == null ) return AuthenticationInfo.None;
        var utcNow = DateTime.UtcNow;
        var read = await center.Center.ReadTokenAsync( monitor, command.Token, utcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( "A relayed command presents an invalid token: it is anonymous." );
            return AuthenticationInfo.None;
        }
        if( command.PresentedBindingSecretHash == null || !FixedTimeEquals( command.PresentedBindingSecretHash, read.BindingSecretHash ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, "A relayed command presents a token without the binding secret of its session: it is anonymous." );
            return AuthenticationInfo.None;
        }
        var session = await center.Sessions.TryReadAsync( monitor, read.Info.UnsafeActualActor.ActorId, read.SessionId ).ConfigureAwait( false );
        if( session == null
            || session.Expires <= utcNow
            || session.ActorId != read.Info.UnsafeActor.ActorId
            || !FixedTimeEquals( session.BindingSecretHash, read.BindingSecretHash ) )
        {
            monitor.Warn( "A relayed command presents the token of a session that ended or changed: it is anonymous." );
            return AuthenticationInfo.None;
        }
        return read.Info;
    }

    static bool FixedTimeEquals( string a, string b ) => CryptographicOperations.FixedTimeEquals( Encoding.ASCII.GetBytes( a ), Encoding.ASCII.GetBytes( b ) );

    static IRelayAuthCenterResult Relayed( PocoDirectory pocos, object? result ) => pocos.Create<IRelayAuthCenterResult>( r => r.Result = result );

    static ICrisResultError Error( PocoDirectory pocos, string text, string resName )
        => pocos.Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) ) );

    [CommandHandler]
    public IAuthCenterEncryptionKey Handle( IActivityMonitor monitor, IGetAuthCenterEncryptionKeyQCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var local = GetLocal( caller );
        if( local == null )
        {
            Throw.InvalidOperationException( $"'{caller}' is not a front of an AuthCenter here." );
        }
        var (publicKey, signature) = local.EncryptionKeys.GetPublished( monitor, local.Party.GetRequiredFeature<ILocalKeys>(), DateTime.UtcNow );
        return pocos.Create<IAuthCenterEncryptionKey>( k =>
        {
            k.PublicKey = publicKey;
            k.Signature = signature;
        } );
    }

    // Every [Sensitive] string must be encrypted for this AuthCenter (in this context): a clear value is refused.
    // The local AuthCenter of a front: the caller is a remote of a local party that is its own AuthCenter, and it
    // allows the feature (it then shares its CrisAuthCenter).
    static LocalAuthCenter? GetLocal( IRemoteParty caller )
    {
        return caller.GetFeature<CrisAuthCenter>() is { } center && center.Owner == caller.Owner
                ? caller.Owner.GetFeature<LocalAuthCenter>()
                : null;
    }

    static bool DecryptSensitiveFields( IActivityMonitor monitor, LocalAuthCenter center, IRemoteParty caller, ICrisPoco command )
    {
        var fields = AuthCenterFieldEncryption.GetSensitiveFields( command.GetType() );
        if( fields == null ) return false;
        var keys = center.EncryptionKeys;
        var utcNow = DateTime.UtcNow;
        foreach( var f in fields )
        {
            if( f.GetValue( command ) is not string value ) continue;
            var context = AuthCenterFieldEncryption.GetContext( center.Party.FullName, caller.FullName, command.CrisPocoModel.PocoName, f.Name );
            if( !AuthCenterFieldEncryption.TryDecrypt( monitor, value, id => keys.Find( id, utcNow ), context, utcNow, out var clear ) )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' relayed '{command.CrisPocoModel.PocoName}' with a '{f.Name}' that cannot be decrypted." );
                return false;
            }
            f.SetValue( command, clear );
        }
        return true;
    }

    static IRelaySessionResult Result( PocoDirectory pocos, object? result ) => pocos.Create<IRelaySessionResult>( r => r.Result = result );

    // A refused session command: a failed ISessionResult, nothing for a logout (it has no result), an ICrisResultError
    // with the message for the other ones (the RedirectedUrl of a start login, the options of a passkey ceremony...).
    static object? Failure( IActivityMonitor monitor, PocoDirectory pocos, ICommandAuthenticationSession command, string text, string resName )
    {
        if( command is ICommand<ISessionResult> c ) return AuthCenterResults.Failure( monitor, c, text, resName );
        monitor.Warn( $"Relayed session command '{command.CrisPocoModel.PocoName}' refused: {text}" );
        if( command is ILogoutSessionCommand ) return null;
        return pocos.Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) ) );
    }
}
