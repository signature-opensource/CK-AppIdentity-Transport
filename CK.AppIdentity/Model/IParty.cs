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
        /// Gets this party's full name. See <see cref="CoreApplicationIdentity.FullName"/>.
        /// </summary>
        NormalizedPath FullName { get; }
    }
}
