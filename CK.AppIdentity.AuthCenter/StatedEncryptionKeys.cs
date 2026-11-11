using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.IO.AuthCenter;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The encryption keys of other parties stated by the Authentication Center (see <see cref="PartyEncryptionKeyStatement"/>),
/// verified with its keys and cached until the end of their use (one minute before). Used by the remote and the anchored
/// sides: only the way they ask the statement differs.
/// </summary>
sealed class StatedEncryptionKeys
{
    readonly CrisAuthCenter _center;
    readonly ConcurrentDictionary<string, (byte[] PublicKey, DateTime Expires)> _keys;

    internal StatedEncryptionKeys( CrisAuthCenter center )
    {
        _center = center;
        _keys = new ConcurrentDictionary<string, (byte[], DateTime)>();
    }

    /// <summary>
    /// Gets a cached key that can still be used.
    /// </summary>
    internal bool TryGet( string partyFullName, DateTime utcNow, out (byte[] PublicKey, DateTime Expires) key )
    {
        return _keys.TryGetValue( partyFullName, out key ) && key.Expires - TimeSpan.FromMinutes( 1 ) > utcNow;
    }

    /// <summary>
    /// Verifies a statement of the Authentication Center about the key of a party and caches it.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="partyFullName">The full name of the party.</param>
    /// <param name="statement">The statement.</param>
    /// <returns>The key and the end of its use, or null when the statement is invalid (a SecurityCritical warning).</returns>
    internal async ValueTask<(byte[] PublicKey, DateTime Expires)?> VerifyAsync( IActivityMonitor monitor, string partyFullName, IPartyEncryptionKeyStatement statement )
    {
        if( statement.PartyFullName != partyFullName
            || !ApplicationSignature.TryRead( statement.Signature, out var signature )
            || await _center.CheckWithKeyEventsAsync( monitor,
                                                     PartyEncryptionKeyStatement.Purpose,
                                                     PartyEncryptionKeyStatement.GetSignedData( partyFullName, statement.PublicKey ),
                                                     signature ).ConfigureAwait( false ) != SignatureVerdict.Valid )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The statement of the AuthCenter '{_center.AuthCenterFullName}' about the encryption key of '{partyFullName}' is invalid." );
            return null;
        }
        var key = (statement.PublicKey, signature.Expiration);
        _keys[partyFullName] = key;
        return key;
    }
}
