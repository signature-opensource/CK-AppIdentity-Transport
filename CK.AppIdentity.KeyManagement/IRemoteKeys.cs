using CK.Core;
using System;
using System.Security.Cryptography;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// <see cref="IRemoteParty"/> public key management.
    /// </summary>
    public interface IRemoteKeys
    {
        /// <summary>
        /// Default maximal allowed clock offset between parties is 5 minutes.
        /// </summary>
        public static readonly TimeSpan DefaultMaxClockOffset = TimeSpan.FromMinutes( 5 );

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
        /// Gets the "MaxClockOffset" configuration option.
        /// Defaults to <see cref="DefaultMaxClockOffset"/>.
        /// Cannot be less than 1 minute and greater than 20 minutes.
        /// </summary>
        TimeSpan MaxClockOffset { get; }

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
        /// This can be called by contexts that have no <see cref="IActivityMonitor"/>: this method accepts any <see cref="IActivityLineEmitter"/>
        /// instead of a classical monitor. 
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="identity">The identity key to trust for this remote or null to clear it.</param>
        /// <returns>True if the new identity has changed, false if it was already set.</returns>
        bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKeyData? identity );

        /// <inheritdoc cref="SetTrustedIdentity(IActivityLineEmitter, RemoteIdentityKeyData?)"/>
        bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKey? identity );

        /// <summary>
        /// Encapsulates the application of a <see cref="ReadTrustInfo"/>:
        /// <list type="bullet">
        ///    <item>
        ///    If we have found our trusted key (<see cref="ReadTrustInfo.FoundTrustedKey"/>), we already trust him but its current remote key
        ///    may have changed: we can safely update it.
        ///    </item>
        ///    <item>
        ///    If we haven't found our trusted key (may be because TrustedIdentity is null), we can avoid a manual enlistment of the remote
        ///    on our side: this depends on the <see cref="AutoTrustKey"/> configuration. This is a "dangerous" option (it defaults to Never).
        ///    </item>
        /// </list>
        /// <para>
        /// This can be called by contexts that have no <see cref="IActivityMonitor"/>: this method accepts any <see cref="IActivityLineEmitter"/>
        /// instead of a classical monitor. 
        /// </para>
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="trustInfo">Read informations.</param>
        /// <returns>True if the <see cref="TrustedIdentity"/> has been updated, false otherwise.</returns>
        bool ApplyReadTrustInfo( IActivityLineEmitter logger, in ReadTrustInfo trustInfo );

        /// <summary>
        /// Checks a clock offset against <see cref="MaxClockOffset"/>.
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="clockOffset">The offset to check.</param>
        /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
        /// <returns>True on success, false if the <paramref name="clockOffset"/> is out of range.</returns>
        bool CheckClockOffset( IActivityLineEmitter logger, TimeSpan clockOffset, LogLevel logLevel = LogLevel.Error );

        /// <summary>
        /// Checks that the provided <paramref name="nonceValue"/> is not already in the cache and adds it.
        /// Checking a nonce value always adds it to the cache. 
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="nonceValue">The nonce value to check and add.</param>
        /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
        /// <returns>True if the nonce has been added.</returns>
        bool CheckAndAddNonceValue( IActivityLineEmitter logger, ulong nonceValue, LogLevel logLevel = LogLevel.Error );

        /// <summary>
        /// Checks that the provided <paramref name="nonce"/> has a UTC creation time, is in range regarding <see cref="MaxClockOffset"/> and
        /// not already in the cache. Checking a potentially valid nonce always adds it to the cache. 
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="nonce">The nonce to check.</param>
        /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
        /// <returns>True on success, false if this nonce is invalid, too old or already known.</returns>
        bool CheckNonce( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error );
    }
}
