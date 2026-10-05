using CK.Cris;

namespace CK.Testing.AppIdentity.Cris;

/// <summary>
/// This command is sent by the Sender and handled by the Listener (<see cref="ListenerHandler.Handle(IWhoAmICommand, CK.AppIdentity.IRemoteParty, CK.Auth.IAuthenticationInfo)"/>):
/// the result is "&lt;calling party full name&gt;/&lt;user name&gt;" as seen by the Listener.
/// </summary>
public interface IWhoAmICommand : ICommand<string>
{
}
