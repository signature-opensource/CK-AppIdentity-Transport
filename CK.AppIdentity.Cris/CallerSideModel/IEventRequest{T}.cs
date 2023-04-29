using CK.Cris;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Strongly typed outgoing request for a <see cref="IEvent"/>.
    /// </summary>
    /// <typeparam name="T">Type of the event.</typeparam>
    public interface IEventRequest<T> : IOutgoingRequest where T : class, IEvent
    {
        /// <summary>
        /// Gets the event.
        /// </summary>
        T Event { get; }
    }
}
