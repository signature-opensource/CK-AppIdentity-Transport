using CK.Auth;
using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// A command executed by the AuthCenter: its handler answers with the actor established by the AuthCenter.
/// </summary>
public interface IWhoAmIAtTheAuthCenterCommand : ICommand<string>, ICommandAuthNormal, ICommandAuthCenter
{
}

/// <summary>
/// A command of the AuthCenter that is not an <see cref="ICommandAuthCenter"/>: a front cannot have it executed there.
/// </summary>
public interface INotAuthCenterCommand : ICommand<string>, ICommandAuthNormal
{
}

/// <summary>
/// The handlers of the test commands, on the AuthCenter only.
/// </summary>
public sealed class AuthCenterOnlyHandlers : ISingletonAutoService
{
    [CommandHandler]
    public string Handle( IWhoAmIAtTheAuthCenterCommand command, AuthenticationInfo authentication ) => $"{authentication.UnsafeActor.ActorName} at the AuthCenter";

    [CommandHandler]
    public string Handle( INotAuthCenterCommand command ) => "Executed.";
}
