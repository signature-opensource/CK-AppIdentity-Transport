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
/// front is never trusted. Commands with sensitive data are refused until their fields are encrypted.
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
            return Result( pocos, Failure( monitor, inner, "Not a front of this AuthCenter.", "Authentication.RelayNotAllowed" ) );
        }
        if( inner.CrisPocoModel.HasSensitiveData )
        {
            return Result( pocos, Failure( monitor, inner, "A command with sensitive data cannot be relayed yet.", "Authentication.SensitiveRelayNotSupported" ) );
        }
        var authentication = AuthenticationInfo.None;
        if( command.Token != null && center.TryReadToken( monitor, command.Token, DateTime.UtcNow, out var info, out _ ) )
        {
            authentication = info;
        }
        var endpoint = new RelayedEndpoint( command );
        await using var scope = _container.GetContainer().CreateAsyncScope( new AuthCenterRelayDIContainerDefinition.Data( monitor, caller, authentication, endpoint ) );
        var services = scope.ServiceProvider;
        object? result;
        var validation = await services.GetRequiredService<RawCrisReceiver>().IncomingValidateAsync( monitor, services, inner ).ConfigureAwait( false );
        if( !validation.Success )
        {
            var text = validation.ValidationMessages.Where( m => m.Level == UserMessageLevel.Error ).Select( m => m.Text ).FirstOrDefault() ?? "Invalid command.";
            result = Failure( monitor, inner, text, "Authentication.InvalidRelayedCommand" );
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

    static IRelaySessionResult Result( PocoDirectory pocos, object? result ) => pocos.Create<IRelaySessionResult>( r => r.Result = result );

    static object? Failure( IActivityMonitor monitor, ICommandAuthenticationSession command, string text, string resName )
        => command is ICommand<ISessionResult> c ? AuthCenterResults.Failure( monitor, c, text, resName ) : null;
}
