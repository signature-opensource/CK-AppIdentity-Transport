using CK.AppIdentity;
using CK.AppIdentity.Cris;
using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace CK.Auth;

/// <summary>
/// Gives a command received from a remote party the identity of its user, vouched for by that caller party:
/// <list type="bullet">
///   <item>
///   The <see cref="AuthenticationInfo.CallerPartyId"/> is the <see cref="IParty.PartyActorId"/> of the caller.
///   A command that carries an identity (an <see cref="IAuthUnsafePart"/> with a non anonymous actor) is refused when
///   the caller has no PartyActorId (0); an anonymous command executes as the anonymous.
///   </item>
///   <item>
///   With the user's proof (see <see cref="IAuthenticationCallContext"/>) and a <see cref="ICallerProofVerifier"/> that
///   accepts it, the identity is the proved one.
///   </item>
///   <item>
///   Otherwise, the actors are read from the command's identifiers and the level is the one the command requires,
///   capped by the receiver's <see cref="ICallerPartyService"/> (without it, any caller party is refused) and never above
///   <see cref="AuthLevel.Normal"/>: a caller party alone never reaches Critical. A command whose required level cannot
///   be granted is refused.
///   </item>
/// </list>
/// </summary>
public sealed class AuthenticationReceptionHandler : ICrisChannelReceptionHandler
{
    readonly CrisAuthenticationService _authentication;
    readonly ICallerPartyService? _callerPolicy;
    readonly ICallerProofVerifier? _proofVerifier;

    /// <summary>
    /// Initializes a new reception handler.
    /// </summary>
    /// <param name="authentication">The authentication service (reads the actors).</param>
    /// <param name="callerPolicy">The policy of this party for its caller parties (none refuses them all).</param>
    /// <param name="proofVerifier">The verifier of the user's proofs, if this party can check them.</param>
    public AuthenticationReceptionHandler( CrisAuthenticationService authentication,
                                           ICallerPartyService? callerPolicy = null,
                                           ICallerProofVerifier? proofVerifier = null )
    {
        _authentication = authentication;
        _callerPolicy = callerPolicy;
        _proofVerifier = proofVerifier;
    }

    /// <inheritdoc />
    public async ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureAsync( IActivityMonitor monitor,
                                                                                             IServiceProvider services,
                                                                                             IRemoteParty caller,
                                                                                             IAbstractCommand command,
                                                                                             ICrisCallContext? callContext )
    {
        int callerId = caller.PartyActorId;
        AuthenticationInfo info = AuthenticationInfo.None;
        if( command is IAuthUnsafePart part && CarriesIdentity( part ) )
        {
            if( callerId == 0 )
            {
                return Refuse( monitor, services, $"'{caller}' has no PartyActorId: it cannot be the caller party of '{command.CrisPocoModel.PocoName}'." );
            }
            AuthenticationInfo? proved = null;
            if( _proofVerifier != null && callContext is IAuthenticationCallContext { Token: not null } proof )
            {
                proved = await _proofVerifier.VerifyAsync( monitor, services, caller, proof ).ConfigureAwait( false );
            }
            if( proved != null )
            {
                info = proved;
            }
            else
            {
                ActorInfo actualActor, actor;
                try
                {
                    (actualActor, actor) = await _authentication.ReadActorsAsync( monitor, part ).ConfigureAwait( false );
                }
                catch( Exception ex )
                {
                    monitor.Error( $"Unable to read the actors of '{command.CrisPocoModel.PocoName}' received from '{caller}'.", ex );
                    return Refuse( monitor, services, $"The actors of '{command.CrisPocoModel.PocoName}' cannot be read." );
                }
                var required = CrisAuthenticationService.GetRequiredLevel( part );
                var granted = _callerPolicy != null
                                ? await _callerPolicy.GetMaxLevelAsync( monitor, callerId, actualActor, actor ).ConfigureAwait( false )
                                : AuthLevel.None;
                // A caller party alone never reaches Critical.
                var level = Min( Min( required, granted ), AuthLevel.Normal );
                if( level < required )
                {
                    return Refuse( monitor, services, $"'{caller}' cannot be the caller party of actor #{actor.ActorId} at level {required} (granted: {level})." );
                }
                info = AuthenticationInfo.CreateRestored( actualActor, actor, level, CrisAuthenticationService.GetDeviceId( part ), DateTime.UtcNow );
            }
        }
        var hub = services.GetRequiredService<AmbientServiceHub>().CleanClone();
        hub.Override( info.WithCallerParty( callerId ) );
        return (null, hub);
    }

    // An identity is carried when the actor (or the actual actor of an impersonation) is not the anonymous.
    static bool CarriesIdentity( IAuthUnsafePart part )
    {
        return part.ActorId is not null and not 0
               || part is IAuthImpersonationPart { ActualActorId: not null and not 0 };
    }

    static AuthLevel Min( AuthLevel a, AuthLevel b ) => a < b ? a : b;

    static (ICrisResultError? Error, AmbientServiceHub? Hub) Refuse( IActivityMonitor monitor, IServiceProvider services, string text )
    {
        monitor.Warn( ActivityMonitor.Tags.SecurityCritical, text );
        var e = services.GetRequiredService<PocoDirectory>().Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, "Authentication.CallerPartyRefused" ) ) );
        return (e, null);
    }
}
