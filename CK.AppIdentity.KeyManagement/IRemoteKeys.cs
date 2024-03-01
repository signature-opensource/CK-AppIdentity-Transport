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
        /// Checks that the provided <paramref name="nonce"/> has a UTC creation time, is valid regarding <see cref="MaxClockOffset"/> and
        /// not already in the cache. Checking a potentially valid nonce always adds it to the cache. 
        /// <para>
        /// Failures are logged. This can be called by "back tasks" that have no <see cref="IActivityMonitor"/> in
        /// their context: this method accepts a <see cref="IActivityLineEmitter"/> instead of a classical monitor. 
        /// </para>
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="nonce">The nonce to check.</param>
        /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
        /// <returns>True on success, false if this nonce is invalid, too old or already known.</returns>
        bool CheckNonce( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error );

        /// <summary>
        /// Checks a clock offset against <see cref="MaxClockOffset"/>.
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="clockOffset">The offset to check.</param>
        /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
        /// <returns>True on success, false if the <paramref name="clockOffset"/> is out of range.</returns>
        bool CheckClockOffset( IActivityLineEmitter logger, TimeSpan clockOffset, LogLevel logLevel = LogLevel.Error );

        /// <summary>
        /// Checks a <paramref name="time"/> (typically a <see cref="TimedNonce.CreationTime"/>) against <see cref="MaxClockOffset"/>.
        /// <para>
        /// The <see cref="TimedNonce.CheckCreationTimeKind(IActivityLineEmitter, string, LogLevel)"/> must have been done before.
        /// This throw if the nonce creation time kind is not UTC.
        /// </para>
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="time">The time to check.</param>
        /// <param name="clockOffset">Outputs the computed offset (that may be invalid).</param>
        /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
        /// <returns>True on success, false if the <paramref name="time"/> is out of range.</returns>
        bool CheckClockOffset( IActivityLineEmitter logger, DateTime time, out TimeSpan clockOffset, LogLevel logLevel = LogLevel.Error );

        /// <summary>
        /// Checks that the provided <paramref name="nonce"/> is valid regarding <see cref="MaxClockOffset"/> and
        /// not already in the cache. Checking a potentially valid nonce always adds it to the cache. 
        /// <para>
        /// The <see cref="TimedNonce.CheckCreationTimeKind(IActivityLineEmitter, string, LogLevel)"/> must have been done before.
        /// This throw if the nonce creation time kind is not UTC.
        /// </para>
        /// <para>
        /// Failures are logged. This can be called by "back tasks" that have no <see cref="IActivityMonitor"/> in
        /// their context: this method accepts a <see cref="IActivityLineEmitter"/> instead of a classical monitor. 
        /// </para>
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="nonce">The nonce to check.</param>
        /// <param name="clockOffset">Outputs the computed offset (that may be invalid).</param>
        /// <param name="validClockOffset">Outputs whether the computed <paramref name="clockOffset"/> is valid.</param>
        /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
        /// <returns>
        /// True on success, false if the clock offset is out of range or the nonce is already known.
        /// When this returns false and <paramref name="validClockOffset"/> is true, this looks like a replay attack.
        /// </returns>
        bool CheckNonce( IActivityLineEmitter logger,
                         in TimedNonce nonce,
                         out TimeSpan clockOffset,
                         out bool validClockOffset,
                         LogLevel logLevel = LogLevel.Error );

        /// <summary>
        /// Checks that the provided <paramref name="nonceValue"/> is not already in the cache and adds it.
        /// Checking a nonce value always adds it to the cache. 
        /// </summary>
        /// <param name="nonceValue">The nonce value to check and add.</param>
        /// <returns>True if the nonce has been added.</returns>
        bool CheckAndAddNonceValue( ulong nonceValue );
    }
}
