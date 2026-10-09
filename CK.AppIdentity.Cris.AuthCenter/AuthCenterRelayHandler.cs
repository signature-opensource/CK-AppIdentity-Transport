using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The Authentication Center side of the relay: executes the session commands relayed by its fronts.
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
        var center = caller.GetFeature<CrisAuthCenter>();
        if( center?.Local == null || center.Owner != caller.Owner )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' is not a front of an AuthCenter here: its relayed '{inner.CrisPocoModel.PocoName}' is refused." );
            return Result( pocos, Failure( monitor, pocos, inner, "Not a front of this AuthCenter.", "Authentication.RelayNotAllowed" ) );
        }
        if( inner.CrisPocoModel.HasSensitiveData && !DecryptSensitiveFields( monitor, center, caller, inner ) )
        {
            return Result( pocos, Failure( monitor, pocos, inner, "The sensitive fields must be encrypted for the AuthCenter.", "Authentication.SensitiveNotEncrypted" ) );
        }
        var authentication = AuthenticationInfo.None;
        if( command.Token != null && await center.ReadTokenAsync( monitor, command.Token, DateTime.UtcNow ).ConfigureAwait( false ) is { } read )
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
    [CommandHandler]
    public IAuthCenterEncryptionKey Handle( IActivityMonitor monitor, IGetAuthCenterEncryptionKeyQCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var center = caller.GetFeature<CrisAuthCenter>();
        if( center?.Local == null || center.Owner != caller.Owner )
        {
            Throw.InvalidOperationException( $"'{caller}' is not a front of an AuthCenter here." );
        }
        var local = center.Local;
        var (publicKey, signature) = local.EncryptionKeys.GetPublished( monitor, local.Party.GetRequiredFeature<ILocalKeys>(), DateTime.UtcNow );
        return pocos.Create<IAuthCenterEncryptionKey>( k =>
        {
            k.PublicKey = publicKey;
            k.Signature = signature;
        } );
    }

    // Every [Sensitive] string must be encrypted for this AuthCenter (in this context): a clear value is refused.
    static bool DecryptSensitiveFields( IActivityMonitor monitor, CrisAuthCenter center, IRemoteParty caller, ICommandAuthenticationSession command )
    {
        Throw.DebugAssert( center.Local != null );
        var fields = AuthCenterFieldEncryption.GetSensitiveFields( command.GetType() );
        if( fields == null ) return false;
        var keys = center.Local.EncryptionKeys;
        var utcNow = DateTime.UtcNow;
        foreach( var f in fields )
        {
            if( f.GetValue( command ) is not string value ) continue;
            var context = AuthCenterFieldEncryption.GetContext( center.AuthCenter.FullName, caller.FullName, command.CrisPocoModel.PocoName, f.Name );
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
