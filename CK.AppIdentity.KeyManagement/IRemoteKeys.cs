using CK.Core;
using System;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// <see cref="IRemoteParty"/> public key management.
    /// </summary>
    public interface IRemoteKeys
    {
        /// <summary>
        /// Gets the <see cref="IOwnedParty.Owner"/> party keys.
        /// </summary>
        ILocalKeys LocalKeys { get; }

        /// <summary>
        /// Gets the remote party.
        /// </summary>
        IRemoteParty Party { get; }

        /// <summary>
        /// Gets the "AutoTrustKey" configuration option.
        /// See <see cref="KeyManagement.AutoTrustKey"/>.
        /// </summary>
        AutoTrustKey AutoTrustKey { get; }

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
        /// This can be called by "back tasks" that have no <see cref="IActivityMonitor"/> in their context:
        /// this method accepts any <see cref="IActivityLineEmitter"/> instead of a classical monitor. 
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="identity">The identity key to trust for this remote or null to clear it.</param>
        /// <returns>True if the new identity has changed, false if it was already set.</returns>
        bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKey? identity );

        /// <summary>
        /// Checks that the provided <paramref name="nonce"/> has not already been used and, optionally,
        /// adds it to the cache.
        /// This can be called by "back tasks" that have no <see cref="IActivityMonitor"/> in their context:
        /// this method accepts any <see cref="IActivityLineEmitter"/> instead of a classical monitor. 
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="utcNow">The <see cref="IApplicationIdentityService.SystemClock"/>' now time.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="addNonce">True to add the nonce to the cache.</param>
        /// <returns>True on success, false if this nonce is already known.</returns>
        bool CheckNonceCache( IActivityLineEmitter logger, DateTime utcNow, ulong nonce, bool addNonce );

        /// <summary>
        /// Adds the provided nonce to the cache.
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="utcNow">The <see cref="IApplicationIdentityService.SystemClock"/>' now time.</param>
        /// <param name="nonce">The nonce.</param>
        void AddNonce( IActivityLineEmitter logger, DateTime utcNow, ulong nonce );
    }
}
