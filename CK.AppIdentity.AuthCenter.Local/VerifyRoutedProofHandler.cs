using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Handles the <see cref="IVerifyRoutedProofQCommand"/>: a party without a channel to this Authentication Center asks it,
/// along its "AuthCenter" route, to verify the user's proof of a command routed to it (the session is alive and still the
/// token's, the session party sealed the command for it). The answer is a statement signed by this Authentication Center
/// (see <see cref="AuthCenterProofStatement"/>): it crosses hops.
/// </summary>
public sealed class VerifyRoutedProofHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the query.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="party">The local party.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The signed statement, or null when the proof is not valid.</returns>
    [CommandHandler]
    public async Task<IAuthCenterProofStatement?> HandleAsync( IActivityMonitor monitor, IVerifyRoutedProofQCommand command, CurrentLocalParty party, PocoDirectory pocos )
    {
        var center = party.LocalParty.GetFeature<LocalAuthCenter>();
        if( center == null )
        {
            monitor.Warn( $"'{party.LocalParty}' is asked to verify a routed user's proof: it is not an Authentication Center." );
            return null;
        }
        if( string.IsNullOrEmpty( command.Destination )
            || command.Nonce is not { Length: AuthCenterProofStatement.NonceSize }
            || command.Token == null || command.BindingSecretHash == null
            || command.RoutedSeal == null || command.RoutedPayloadDigest == null || command.RoutedSignature == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"An incomplete verification of a user's proof routed to '{command.Destination}' is refused." );
            return null;
        }
        var seal = new RoutedProofSeal( command.RoutedSeal, command.RoutedPayloadDigest, command.RoutedSignature );
        // The seal must have been made for the destination: the statement names it, the asking party checks it is itself.
        var info = await center.CheckProofAsync( monitor, command.Token, command.BindingSecretHash, seal, command.Destination ).ConfigureAwait( false );
        if( info == null ) return null;
        var signature = center.Party.GetRequiredFeature<ILocalKeys>()
                              .Sign( AuthCenterProofStatement.Purpose,
                                     AuthCenterProofStatement.GetSignedData( command.Destination, command.Nonce, command.Token, seal ),
                                     DateTime.UtcNow + AuthCenterProofStatement.Lifetime );
        monitor.Trace( $"A user's proof routed to '{command.Destination}' is verified: actor #{info.UnsafeActor.ActorId}." );
        return pocos.Create<IAuthCenterProofStatement>( s => s.Signature = signature.Encoded.ToArray() );
    }
}
