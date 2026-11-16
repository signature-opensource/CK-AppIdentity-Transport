using CK.Cris;

namespace CK.Testing.Engine.AppIdentity.Cris;

/// <summary>
/// This command is sent by the Listener and handled by
/// the Sender (<see cref="SenderHandler.Handle(IListenerCommand)"/>).
/// </summary>
public interface IListenerCommand : ICommand<string>
{
    string Message { get; set; }
}
