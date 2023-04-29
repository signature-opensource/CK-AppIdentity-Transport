using CK.Cris;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Strongly typed request for <see cref="ICrisEvent"/>.
    /// </summary>
    /// <typeparam name="T">Type of the command.</typeparam>
    public interface IEventRequest<T> : IRequest where T : class, IEvent
    {
        /// <summary>
        /// Gets the event.
        /// </summary>
        T Event { get; }
    }
}
