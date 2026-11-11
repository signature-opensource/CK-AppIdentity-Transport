using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The Authentication Center of a local party that has no channel to it: it is designated by its full name
/// ("Local:AuthCenterParty") and has a trust anchor. Its keys come from the key directory (verified from the anchor), and
/// what this party asks it travels along its <see cref="AuthCenterFeature.RouteName"/> route, answered by statements it
/// signs: a hop can withhold them, not forge them.
/// <list type="bullet">
///   <item>A user's proof received directly is read here (the token with the keys of the Authentication Center, and its
///   binding): its session is not asked, a logout takes effect at the end of the critical window.</item>
///   <item>A user's proof received with a routed command is verified by the Authentication Center
///   (<see cref="IVerifyRoutedProofQCommand"/>, the proof encrypted for it: the hops never hold it): the seal of the
///   session party can be checked only there. The liveness of its session is checked at the same time.</item>
///   <item>The encryption keys of the Authentication Center and of its remotes are its statements
///   (<see cref="IGetRemoteEncryptionKeyQCommand"/>).</item>
/// </list>
/// </summary>
public sealed class AnchoredAuthCenter : IAuthCenterProofChecker, IPartyEncryptionKeyDirectory
{
    readonly CrisAuthCenter _center;
    readonly PartyRoutedCommandSender _sender;
    readonly IServiceProvider _services;
    readonly StatedEncryptionKeys _partyKeys;

    internal AnchoredAuthCenter( CrisAuthCenter center, PartyRoutedCommandSender sender, IServiceProvider services )
    {
        Throw.DebugAssert( center.AuthCenter == null );
        _center = center;
        _sender = sender;
        _services = services;
        _partyKeys = new StatedEncryptionKeys( center );
    }

    /// <summary>
    /// Gets the shared <see cref="CrisAuthCenter"/> feature (its <see cref="CrisAuthCenter.AuthCenter"/> is null).
    /// </summary>
    public CrisAuthCenter Center => _center;

    /// <summary>
    /// Checks a user's proof received directly: it is read here, the liveness of its session is not asked (see
    /// <see cref="CheckLivenessAsync"/>).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <returns>The proved identity, or null when the proof is not valid (the reason is logged).</returns>
    public async ValueTask<AuthenticationInfo?> CheckProofAsync( IActivityMonitor monitor, string token, byte[] bindingSecretHash )
    {
        var read = await _center.ReadProofAsync( monitor, token, bindingSecretHash, _center.UtcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( "An invalid user's proof is ignored." );
            return null;
        }
        return await CheckLivenessAsync( monitor, token, read, null ).ConfigureAwait( false );
    }

    /// <summary>
    /// For a proof received directly, its reading is enough: without a channel to the Authentication Center, the liveness
    /// of its session is not asked (a logout or a revocation takes effect at the end of the critical window). For the proof
    /// of a routed command, the Authentication Center is asked along its route: it checks the seal of the session party
    /// and the liveness, and answers with a statement it signs, verified here with its keys. The proof is encrypted for the
    /// Authentication Center (its key is its own statement, see <see cref="GetPartyEncryptionKeyAsync"/>): without its
    /// key, nothing is sent and the proof is not verified (fail closed).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="read">The content of the token, read with its binding secret.</param>
    /// <param name="seal">The seal of the routed command that carried the proof, null for a proof received directly.</param>
    /// <returns>The proved identity, or null when the proof is not verified (the reason is logged).</returns>
    public async ValueTask<AuthenticationInfo?> CheckLivenessAsync( IActivityMonitor monitor, string token, AuthCenterTokenContent read, RoutedProofSeal? seal )
    {
        Throw.CheckNotNullArgument( token );
        Throw.CheckNotNullArgument( read );
        if( seal == null )
        {
            monitor.Trace( $"A user's proof is read locally: its session is not asked (no channel to the AuthCenter '{_center.AuthCenterFullName}')." );
            return read.Info;
        }
        var destination = _center.Owner.FullName.Path;
        var nonce = RandomNumberGenerator.GetBytes( AuthCenterProofStatement.NonceSize );
        var encryptedProof = await EncryptProofAsync( monitor, destination, nonce, token, read.BindingSecretHash ).ConfigureAwait( false );
        if( encryptedProof == null ) return null;
        var answer = await SendAsync( monitor, pocos => CreateVerifyQuery( pocos, destination, nonce, encryptedProof, seal ), "verify a routed user's proof" ).ConfigureAwait( false );
        if( answer is not IAuthCenterProofStatement statement )
        {
            if( answer == null ) monitor.Warn( $"The AuthCenter '{_center.AuthCenterFullName}' refused the user's proof routed to '{destination}' (its session or its seal)." );
            return null;
        }
        if( !ApplicationSignature.TryRead( statement.Signature, out var signature )
            || await _center.CheckWithKeyEventsAsync( monitor,
                                                     AuthCenterProofStatement.Purpose,
                                                     AuthCenterProofStatement.GetSignedData( destination, nonce, token, seal ),
                                                     signature ).ConfigureAwait( false ) != SignatureVerdict.Valid )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The statement of the AuthCenter '{_center.AuthCenterFullName}' about a user's proof routed to '{destination}' is invalid: the proof is ignored." );
            return null;
        }
        return read.Info;
    }

    // Encrypts the user's proof for the Authentication Center: the hops on its route never hold it.
    internal async ValueTask<byte[]?> EncryptProofAsync( IActivityMonitor monitor, string destination, byte[] nonce, string token, byte[] bindingSecretHash )
    {
        var key = await GetPartyEncryptionKeyAsync( monitor, _center.AuthCenterFullName ).ConfigureAwait( false );
        if( key == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"No verified encryption key for the AuthCenter '{_center.AuthCenterFullName}': the user's proof routed to '{destination}' can't be verified, it is ignored." );
            return null;
        }
        return AuthCenterProofStatement.EncryptProof( key.Value.PublicKey, destination, nonce, token, bindingSecretHash, _center.UtcNow );
    }

    internal static IVerifyRoutedProofQCommand CreateVerifyQuery( PocoDirectory pocos, string destination, byte[] nonce, byte[] encryptedProof, RoutedProofSeal seal )
    {
        return pocos.Create<IVerifyRoutedProofQCommand>( c =>
        {
            c.Destination = destination;
            c.Nonce = nonce;
            c.EncryptedProof = encryptedProof;
            c.RoutedSeal = seal.Header;
            c.RoutedPayloadDigest = seal.PayloadDigest;
            c.RoutedSignature = seal.Signature;
        } );
    }

    /// <summary>
    /// Gets the verified encryption key of the Authentication Center or of one of its remotes (see
    /// <see cref="IPartyEncryptionKeyDirectory"/>): the statement of the Authentication Center, asked along its route
    /// (<see cref="IGetRemoteEncryptionKeyQCommand"/>). A statement is cached until the key ends.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="partyFullName">The full name of the party.</param>
    /// <returns>The public key and the end of its use, or null when it is unknown (the reason is logged).</returns>
    public async ValueTask<(byte[] PublicKey, DateTime Expires)?> GetPartyEncryptionKeyAsync( IActivityMonitor monitor, string partyFullName )
    {
        Throw.CheckNotNullArgument( partyFullName );
        if( _partyKeys.TryGet( partyFullName, _center.UtcNow, out var cached ) )
        {
            return cached;
        }
        var answer = await SendAsync( monitor,
                                      pocos => pocos.Create<IGetRemoteEncryptionKeyQCommand>( c => c.PartyFullName = partyFullName ),
                                      $"ask the encryption key of '{partyFullName}'" ).ConfigureAwait( false );
        if( answer is not IPartyEncryptionKeyStatement statement )
        {
            if( answer == null ) monitor.Warn( $"The AuthCenter '{_center.AuthCenterFullName}' doesn't know the encryption key of '{partyFullName}'." );
            return null;
        }
        return await _partyKeys.VerifyAsync( monitor, partyFullName, statement ).ConfigureAwait( false );

    }

    // Sends a query along the route of the AuthCenter. Null when it answered null, or when it can't be sent or answered
    // (an error is logged): the result is an ICrisResultError then.
    internal async Task<object?> SendAsync( IActivityMonitor monitor, Func<PocoDirectory, IAbstractCommand> create, string what )
    {
        await using var scope = _services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        object? result;
        try
        {
            var command = create( services.GetRequiredService<PocoDirectory>() );
            // Bounded by the sender's timeout: the scope outlives the send.
            result = await _sender.SendAsync( monitor, services, _center.Owner, command, AuthCenterFeature.RouteName, _center.AuthCenterFullName ).ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to {what} along the route of the AuthCenter '{_center.AuthCenterFullName}'.", ex );
            return services.GetRequiredService<PocoDirectory>().Create<ICrisResultError>();
        }
        if( result is ICrisResultError e )
        {
            monitor.Warn( $"Unable to {what} along the route of the AuthCenter '{_center.AuthCenterFullName}': {e.Errors.Select( m => m.Text ).Concatenate()}" );
        }
        return result;
    }

    /// <summary>
    /// Overridden to return the Authentication Center and its owner.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => _center.ToString();
}
