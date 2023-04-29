using CK.PerfectEvent;
using System.Collections.Generic;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Thread safe collection of <typeparamref name="T"/> where items can
    /// only be added. The <see cref="Added"/> event is raised on new items.
    /// </summary>
    /// <typeparam name="TContainer">The type of the item's container.</typeparam>
    /// <typeparam name="T">The type of the item.</typeparam>
    public interface ICollector<TContainer, T> : IReadOnlyCollection<T> where T : class
    {
        /// <summary>
        /// Raised when a new item appears.
        /// </summary>
        PerfectEvent<TContainer, T> Added { get; }
    }
}
