using CK.Core;
using System;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// What a local party and a remote party have in common: checking what the party signed with
/// <see cref="ILocalKeys.Sign"/>. Both <see cref="ILocalKeys"/> and <see cref="IRemoteKeys"/> are one, so
/// <c>party.GetFeature&lt;IPartyKeys&gt;()</c> answers whichever the party is.
/// <para>
/// Deliberately minimal: what the identity is (its key event log, whether it has ended) is the business
/// of the specific interfaces. <see cref="Verify"/> takes all of it into account and says why it refuses.
/// </para>
/// </summary>
public interface IPartyKeys
{
    /// <summary>
    /// Gets the party.
    /// </summary>
    IParty Party { get; }

    /// <summary>
    /// Verifies a signature made by this party with <see cref="ILocalKeys.Sign"/>.
    /// <para>
    /// A signature is valid until its expiration, unless the party's identity is revoked: a regular
    /// rotation has no effect on it, a recovery condemns everything signed before it. A remote must be
    /// pinned. The expiration check is strict: no clock offset is tolerated on it.
    /// </para>
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="purpose">The purpose the signature was made for.</param>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">
    /// The signature. Stored or received bytes are read back by <see cref="ApplicationSignature.TryRead"/>.
    /// </param>
    /// <returns>True if the signature is valid now.</returns>
    bool Verify( IActivityLineEmitter logger,
                 string purpose,
                 ReadOnlySpan<byte> data,
                 in ApplicationSignature signature );
}
