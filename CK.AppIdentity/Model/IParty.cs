using CK.Core;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity
{

    /// <summary>
    /// Generalizes <see cref="ILocalParty"/> and <see cref="IRemoteParty"/>.
    /// </summary>
    public interface IParty : IAppIdentityObject
    {
        /// <summary>
        /// Gets the application identity.
        /// This can be the root <see cref="ApplicationIdentityService"/> or a <see cref="DomainApplicationIdentity"/>.
        /// </summary>
        IApplicationIdentity ApplicationIdentity { get; }

        /// <summary>
        /// Gets this party's full name. See <see cref="CoreApplicationIdentity.FullName"/>.
        /// </summary>
        NormalizedPath FullName { get; }

        /// <summary>
        /// Gets whether this party is hosted by the root <see cref="ApplicationIdentityService"/>
        /// or by a subordinated <see cref="IRemoteParty.DomainApplicationIdentity"/>.
        /// </summary>
        bool IsRooted { get; }

        /// <summary>
        /// Gets whether this party has been removed from the root <see cref="ApplicationIdentityService"/>.
        /// </summary>
        bool IsDestroyed { get; }
    }
}
