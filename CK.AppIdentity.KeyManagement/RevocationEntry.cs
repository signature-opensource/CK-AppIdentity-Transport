using CK.Core;
using System;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// A revoked identity: the key event log of a party, named by its identity (see <see cref="KeyEvent.GetIdentity"/>), is
/// refused forever. A party that incepts again starts another log: it is not revoked. The entries come from a list signed
/// by the Authentication Center (see <see cref="ILocalKeys.SetRevocationsAsync"/>).
/// </summary>
public sealed class RevocationEntry
{
    readonly byte[] _identity;

    /// <summary>
    /// Initializes a new entry.
    /// </summary>
    /// <param name="fullName">The full name of the revoked party.</param>
    /// <param name="identity">The identity of its revoked log (<see cref="KeyEvent.HashSize"/> bytes).</param>
    /// <param name="revokedAt">When it has been revoked.</param>
    /// <param name="nameBanned">Whether the full name is also refused in the routed commands and the routes.</param>
    public RevocationEntry( string fullName, ReadOnlySpan<byte> identity, DateTime revokedAt, bool nameBanned )
    {
        Throw.CheckNotNullOrEmptyArgument( fullName );
        Throw.CheckArgument( identity.Length == KeyEvent.HashSize );
        FullName = fullName;
        _identity = identity.ToArray();
        RevokedAt = revokedAt;
        NameBanned = nameBanned;
    }

    /// <summary>
    /// Gets the full name of the revoked party.
    /// </summary>
    public string FullName { get; }

    /// <summary>
    /// Gets the identity of its revoked log.
    /// </summary>
    public ReadOnlyMemory<byte> Identity => _identity;

    /// <summary>
    /// Gets when it has been revoked.
    /// </summary>
    public DateTime RevokedAt { get; }

    /// <summary>
    /// Gets whether the full name is also refused in the routed commands and the routes (until it is readmitted).
    /// </summary>
    public bool NameBanned { get; }

    /// <summary>
    /// Gets whether this entry revokes a log identity.
    /// </summary>
    /// <param name="identity">A log identity.</param>
    /// <returns>True when it is the revoked one.</returns>
    public bool Matches( ReadOnlySpan<byte> identity ) => identity.SequenceEqual( _identity );

    /// <inheritdoc />
    public override string ToString() => $"'{FullName}' ({Convert.ToHexStringLower( _identity, 0, 6 )}) revoked at {RevokedAt:O}";
}
