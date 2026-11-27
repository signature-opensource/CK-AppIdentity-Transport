using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The configuration of the "KeyManagement" feature (<see cref="KeyManagementFeatureDriver"/>).
/// <list type="bullet">
///   <item>The keys of a local party (in its "Local") are its security settings: they are read on the party only, never
///   from a "Defaults" above it (<see cref="ConfigurationNoDefaultsAttribute"/>: a value in a "Defaults" is an error).</item>
///   <item>The keys of a remote (<see cref="AutoTrustKey"/>, <see cref="MaxClockOffset"/>) are read along the levels: the
///   remote, then the "Defaults" above it.</item>
/// </list>
/// </summary>
[ConfigurationModel]
public sealed class KeyManagementConfiguration : IConfigurationModel
{
    /// <summary>
    /// Gets the offline recovery key of a local party: the base64 SubjectPublicKeyInfo of a P-256 key generated and kept
    /// offline. Without it, the recovery key is kept in the key store.
    /// </summary>
    [ConfigurationNoDefaults]
    public string? RecoveryPublicKey { get; init; }

    /// <summary>
    /// Gets the number of days of a key of a local party before its rotation.
    /// </summary>
    [ConfigurationNoDefaults]
    public int? KeyRotationDays { get; init; }

    /// <summary>
    /// Gets the number of days of an operational key of a local party.
    /// </summary>
    [ConfigurationNoDefaults]
    public int? OperationalKeyDays { get; init; }

    /// <summary>
    /// Gets the maximal number of days of a signature of a local party (bounded by the <see cref="KeyRotationDays"/>).
    /// </summary>
    [ConfigurationNoDefaults]
    public int? MaxSignatureDays { get; init; }

    /// <summary>
    /// Gets the pre-authorized enlistment ticket of a local party (a secret).
    /// </summary>
    [ConfigurationNoDefaults]
    public string? EnlistTicket { get; init; }

    /// <summary>
    /// Gets the trust anchors of a local party: by full name of the anchored party, a checkpoint of its key event log, or
    /// "#Dev" in the dev store of a development solution.
    /// </summary>
    [ConfigurationNoDefaults]
    public IReadOnlyDictionary<string, string>? TrustAnchors { get; init; }

    /// <summary>
    /// Gets the secret key that encrypts the DataProtection key ring of the root party (a secret: the base64 of 32
    /// random bytes).
    /// </summary>
    [ConfigurationNoDefaults]
    public string? KeyRingKey { get; init; }

    /// <summary>
    /// Gets the previous secret key of the DataProtection key ring of the root party (a secret): it only decrypts.
    /// </summary>
    [ConfigurationNoDefaults]
    public string? KeyRingPreviousKey { get; init; }

    /// <summary>
    /// Gets whether the key of a remote is trusted on first use (<see cref="KeyManagement.AutoTrustKey.Never"/> by default).
    /// </summary>
    public AutoTrustKey? AutoTrustKey { get; init; }

    /// <summary>
    /// Gets the maximal clock offset accepted with a remote: between 1 and 20 minutes.
    /// </summary>
    public TimeSpan? MaxClockOffset { get; init; }

    /// <inheritdoc />
    public void Validate( IConfigurationValidationContext context )
    {
        // A combination of names ("Never, Once") is not a value: this is a security switch, a typo must not grant trust.
        if( AutoTrustKey is { } a && !Enum.IsDefined( a ) ) context.Error( $"'{context.Path}:AutoTrustKey' must be '{KeyManagement.AutoTrustKey.Never}' or '{KeyManagement.AutoTrustKey.Once}'." );
        if( MaxClockOffset is { } o && (o < TimeSpan.FromMinutes( 1 ) || o > TimeSpan.FromMinutes( 20 )) )
        {
            context.Error( $"'{context.Path}:MaxClockOffset' is {o}: between '00:01:00' (1 minute) and '00:20:00' (20 minutes) is expected." );
        }
    }
}
