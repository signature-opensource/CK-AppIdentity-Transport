using CK.Cris;

namespace CK.Testing.AppIdentity.Cris;

/// <summary>
/// Caller only immediate event emitted by <see cref="ListenerHandler.HandleAsync(ISenderCommand, ICrisCommandContext)"/>.
/// </summary>
[ImmediateEvent]
public interface IListenerImmediateEvent : IEvent
{
    string Message { get; set; }
}
