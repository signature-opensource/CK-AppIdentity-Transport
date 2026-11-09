using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Handles the <see cref="IGetRemoteEncryptionKeyQCommand"/> of a remote of the Authentication Center (the key directory):
/// the encryption key of one of its remotes (or its own), verified, in a statement it signs (see
/// <see cref="PartyEncryptionKeyStatement"/>).
/// </summary>
public sealed class PartyEncryptionKeyDirectoryHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the query.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="caller">The remote that sent it.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The statement, or null when the party is unknown or publishes no key.</returns>
    [CommandHandler]
    public async Task<IPartyEncryptionKeyStatement?> HandleAsync( IActivityMonitor monitor, IGetRemoteEncryptionKeyQCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var local = LocalAuthCenter.GetLocal( caller );
        if( local == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' asks '{caller.Owner}' the encryption key of '{command.PartyFullName}': it is not a remote of an Authentication Center here." );
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
