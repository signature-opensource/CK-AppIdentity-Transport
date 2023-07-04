using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// <see cref="IRemoteParty"/> public key management.
    /// </summary>
    public interface IRemoteKeys
    {
        /// <summary>
        /// Gets the remote party.
        /// </summary>
        IRemoteParty Party { get; }

        /// <summary>
        /// Gets the trusted identity.
        /// <para>
        /// When not null, any incoming connection must present at least this identity.
        /// </para>
        /// This is automatically updated during the lifetime of a remote at each
        /// connection when the trusted remote renews its identity key.
        /// </summary>
        RemoteIdentityKey? TrustedIdentity { get; }

        /// <summary>
        /// Sets or clears the trusted identity. 
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="identity">The identity key to trust for this remote or null to clear it.</param>
        /// <returns>True if the new identity has changed, false if it was already set.</returns>
        bool SetTrustedIdentity( IActivityMonitor monitor, RemoteIdentityKey? identity );
    }
}
