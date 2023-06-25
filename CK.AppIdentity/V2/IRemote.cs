using CK.Core;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    public interface IRemote : IApplicationIdentityObject
    {
        /// <summary>
        /// Gets this remote's domain.
        /// This can be the root <see cref="ApplicationIdentityService"/> or a <see cref="RemoteDomain"/>.
        /// </summary>
        ApplicationIdentityDomain Domain { get; }

        /// <summary>
        /// Gets whether this remote is hosted by the root <see cref="ApplicationIdentityService"/>
        /// or by a subordinated <see cref="RemoteDomain"/>.
        /// </summary>
        bool IsRooted { get; }

        /// <summary>
        /// Gets whether this is a dynamic remote.
        /// </summary>
        bool IsDynamic { get; }

        /// <summary>
        /// Gets whether this remote has been removed from the root <see cref="ApplicationIdentityService"/>.
        /// </summary>
        bool IsDestroyed { get; }

        /// <summary>
        /// Initiates the destruction of this remote. <see cref="IsDynamic"/> must be true
        /// otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        /// <returns>True if this call destroyed this remote, false it is already destroyed.</returns>
        bool SetDestroyed();

        /// <summary>
        /// Destroys this remote. Even if <see cref="SetDestroyed"/> has been called, awaiting this
        /// waits for this remote to be actually destroyed (this can always be awaited).
        /// <para>
        /// <see cref="IsDynamic"/> must be true otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </para>
        /// </summary>
        /// <returns>The awaitable.</returns>
        Task DestroyAsync();

        /// <summary>
        /// Internal point.
        /// </summary>
        /// <param name="isTop"></param>
        internal void DoSetDestroyed( bool isTop );
    }
}
