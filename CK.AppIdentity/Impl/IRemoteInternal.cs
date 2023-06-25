using System.Threading.Tasks;

namespace CK.AppIdentity
{
    interface IRemoteInternal : IRemote
    {
        /// <summary>
        /// Sets the destroyed flag (recursively on a composite) and
        /// calls <see cref="AppIdentityAgent.OnDestroy(IRemote)"/> on the
        /// top destroyed remote.
        /// </summary>
        /// <param name="isTop">Whether this remote is the root of the destruction.</param>
        void DoSetDestroyed( bool isTop );

        /// <summary>
        /// Gets the destroyed task source.
        /// </summary>
        TaskCompletionSource? DestroyTCS { get; }

        new IRemoteOwnerInternal Owner { get; }
    }
}
