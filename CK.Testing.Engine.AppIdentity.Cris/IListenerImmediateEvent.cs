using CK.Cris;

namespace CK.Testing.Engine.AppIdentity.Cris;

/// <summary>
/// Caller only immediate event emitted by <see cref="ListenerHandler.HandleAsync(ISenderCommand, ICrisCommandContext)"/>.
/// </summary>
[ImmediateEvent]
public interface IListenerImmediateEvent : IEvent
{
    string Message { get; set; }
}
