using CK.Core;
using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// Asks the Authentication Center the encryption key of one of its remotes (the key directory): it answers with a statement
/// it signs, from the description of the remote (verified with its pinned keys). Null when the party is unknown or publishes
/// no key. Internal to the System and executed by the receiving endpoint only (the handler answers its remotes only).
/// </summary>
[Internal]
public interface IGetRemoteEncryptionKeyQCommand : ICommand<IPartyEncryptionKeyStatement?>, ICommandEndpointOnly
{
    /// <summary>
    /// Gets or sets the full name of the party.
    /// </summary>
    string PartyFullName { get; set; }
}

/// <summary>
/// The statement of the Authentication Center about the encryption key of a party: its signature covers the full name of
/// the party and its public key; its expiration is the end of use of the key.
/// </summary>
public interface IPartyEncryptionKeyStatement : IPoco
{
    /// <summary>
    /// Gets or sets the full name of the party.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the public key (SubjectPublicKeyInfo).
    /// </summary>
    byte[] PublicKey { get; set; }

    /// <summary>
    /// Gets or sets the encoded signature of the statement by the Authentication Center.
    /// </summary>
    byte[] Signature { get; set; }
}
