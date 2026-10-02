using CK.Cris;

namespace CK.Testing.AppIdentity.Cris;

/// <summary>
/// This command is sent by the Sender and handled by
/// the Listener (<see cref="ListenerHandler.Handle(ISenderCommand)"/>).
/// </summary>
public interface ISenderCommand : ICommand<string>
{
    string Message { get; set; }
}
