using Microsoft.AspNetCore.DataProtection;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// <see cref="ILocalParty"/> key management: handles the private keys
/// of the party.
/// </summary>
public interface ILocalKeys
{
    /// <summary>
    /// Minimal number of days for <see cref="AllowedOfflineDays"/>.
    /// </summary>
    const int MinAllowedOfflineDays = 7;

    /// <summary>
    /// Maximal number of days for <see cref="AllowedOfflineDays"/>: ten years.
    /// <para>
    /// The value is scaled and handed to <c>DateTime.AddDays</c> to compute a certificate expiry, so
    /// leaving it unbounded lets a configuration typo throw out of the key builder and stop the
    /// service from starting at all, rather than being clamped and warned about.
    /// </para>
    /// </summary>
    const int MaxAllowedOfflineDays = 3650;

    /// <summary>
    /// Default value of <see cref="AllowedOfflineDays"/>.
    /// </summary>
    const int DefaultAllowedOfflineDays = 60;

    /// <summary>
    /// The maximum count of simultaneously valid identity keys.
    /// </summary>
    const int MaxIdentityCount = 8;

    /// <summary>
    /// The maximum public key size (actual ECDsa public key sizes are far smaller).
    /// </summary>
    const int MaxPublicKeySize = 2048;

    /// <summary>
    /// Gets the local party.
    /// </summary>
    ILocalParty Party { get; }

    /// <summary>
    /// Gets the number of days during which this party or a remote party can be offline
    /// without losing their identities.
    /// <para>
    /// This drives the expiration delays of identity keys: identity keys are created with
    /// a lifetime that is twice this value (with a one day security).
    /// </para>
    /// </summary>
    int AllowedOfflineDays { get; }

    /// <summary>
    /// Gets the current identity key (the first one of <see cref="Identities"/>).
    /// </summary>
    LocalIdentityKey CurrentIdentity { get; }

    /// <summary>
    /// Gets the identity keys. The first one is the current one,
    /// the other ones are still valid but obsolete.
    /// </summary>
    IReadOnlyList<LocalIdentityKey> Identities { get; }

    /// <summary>
    /// Gets a data protector for this party.
    /// This should be used to protect tokens-like data (small blocks).
    /// </summary>
    IDataProtector Protector { get; }
}
