using CK.Core;
using System;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// A feature of a local party that knows the verified encryption keys of the parties of the System (see
/// <see cref="KeyManagement.PartyEncryption"/>): the <c>LocalAuthCenter</c> of the Authentication Center reads the
/// descriptions of its remotes, the <c>RemoteAuthCenter</c> of a remote asks the Authentication Center (the key directory:
/// <c>IGetRemoteEncryptionKeyQCommand</c>), that vouches for the keys of its remotes.
/// <para>
/// This is what lets a party encrypt for a party that is not one of its remotes, without trusting the path: the key is
/// stated by the Authentication Center, whose keys it has.
/// </para>
/// </summary>
public interface IPartyEncryptionKeyDirectory
{
    /// <summary>
    /// Gets the verified encryption key of a party: the Authentication Center itself or one of its remotes.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="partyFullName">The full name of the party.</param>
    /// <returns>The public key (SubjectPublicKeyInfo) and the end of its use, or null when it is unknown (the reason is logged).</returns>
    ValueTask<(byte[] PublicKey, DateTime Expires)?> GetPartyEncryptionKeyAsync( IActivityMonitor monitor, string partyFullName );
}

/// <summary>
/// The statement of the key directory (see <see cref="IPartyEncryptionKeyDirectory"/>): the Authentication Center signs
/// "the encryption key of the party X is K" (<see cref="Purpose"/>), until the end of use of the key (the expiration of the
/// signature).
/// </summary>
public static class PartyEncryptionKeyStatement
{
    /// <summary>
    /// The purpose of the signature of a statement by the Authentication Center.
    /// </summary>
    public const string Purpose = "CK.AuthCenter.PartyEncryptionKey";

    /// <summary>
    /// Gets the data signed by a statement: the UTF-8 full name of the party, a zero, then its public key.
    /// </summary>
    /// <param name="partyFullName">The full name of the party.</param>
    /// <param name="publicKey">Its public key.</param>
    /// <returns>The signed data.</returns>
    public static byte[] GetSignedData( string partyFullName, ReadOnlySpan<byte> publicKey )
    {
        var name = Encoding.UTF8.GetBytes( partyFullName );
        var data = new byte[name.Length + 1 + publicKey.Length];
        name.CopyTo( data, 0 );
        publicKey.CopyTo( data.AsSpan( name.Length + 1 ) );
        return data;
    }
}
