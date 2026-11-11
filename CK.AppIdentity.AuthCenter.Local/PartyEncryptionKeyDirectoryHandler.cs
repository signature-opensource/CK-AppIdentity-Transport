using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Handles the <see cref="IGetRemoteEncryptionKeyQCommand"/> of a party of the System (the key directory), received
/// directly or along the "AuthCenter" route: the encryption key of one of the remotes of the Authentication Center (or its
/// own), verified, in a statement it signs (see <see cref="PartyEncryptionKeyStatement"/>).
/// </summary>
public sealed class PartyEncryptionKeyDirectoryHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the query.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="party">The local party.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The statement, or null when the party is unknown or publishes no key.</returns>
    [CommandHandler]
    public async Task<IPartyEncryptionKeyStatement?> HandleAsync( IActivityMonitor monitor, IGetRemoteEncryptionKeyQCommand command, CurrentLocalParty party, PocoDirectory pocos )
    {
        var local = party.LocalParty.GetFeature<LocalAuthCenter>();
        if( local == null )
        {
            monitor.Warn( $"'{party.LocalParty}' is asked the encryption key of '{command.PartyFullName}': it is not an Authentication Center." );
            return null;
        }
        var key = await local.GetPartyEncryptionKeyAsync( monitor, command.PartyFullName ).ConfigureAwait( false );
        if( key == null ) return null;
        var (publicKey, expires) = key.Value;
        var signature = local.Party.GetRequiredFeature<ILocalKeys>().Sign( PartyEncryptionKeyStatement.Purpose,
                                                                           PartyEncryptionKeyStatement.GetSignedData( command.PartyFullName, publicKey ),
                                                                           expires );
        return pocos.Create<IPartyEncryptionKeyStatement>( s =>
        {
            s.PartyFullName = command.PartyFullName;
            s.PublicKey = publicKey;
            s.Signature = signature.Encoded.ToArray();
        } );
    }
}
