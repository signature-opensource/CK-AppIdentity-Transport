using CK.AppIdentity.Cris;
using CK.AppIdentity.Enlistment;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.AppIdentity.TransportLayer;
using CK.IO.AppIdentity.Enlistment;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter.Enlistment;

/// <summary>
/// Asks the Authentication Center to countersign the statement of an approval: sent by the host of the approval page in
/// the request of the operator (the Critical level: the operator's live proof travels with it). The Authentication Center
/// checks that the operator is the one of the statement, not impersonated, and that the caller party is its host. The
/// right to enlist can be checked here by the application (a validator of this command, on the Authentication Center).
/// </summary>
[Internal]
public interface ICountersignApprovalCommand : ICommand<ICountersignApprovalResult?>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the statement, signed by the host.
    /// </summary>
    IPartyApprovalStatement? Statement { get; set; }

    /// <summary>
    /// Gets or sets whether the approved party waits on the holder and must approve it too (a "both approval"): the
    /// Authentication Center also signs a <see cref="PinGrant"/> of the holder for the approved party, when it knows the
    /// holder (its pin of a remote, or its anchor).
    /// </summary>
    bool WithPinGrant { get; set; }

    /// <summary>
    /// Gets or sets whether a holder approved the key of the <see cref="Statement"/>, that the Authentication Center
    /// countersigned before (its countersignature is in the statement): the Authentication Center then authorizes the
    /// routes of the statement for the approved party, it doesn't sign again.
    /// </summary>
    bool Approved { get; set; }
}

/// <summary>
/// The result of the <see cref="ICountersignApprovalCommand"/>.
/// </summary>
public interface ICountersignApprovalResult : IPoco
{
    /// <summary>
    /// Gets or sets the encoded countersignature.
    /// </summary>
    byte[] Countersignature { get; set; }

    /// <summary>
    /// Gets or sets the encoded <see cref="PinGrant"/>, null when none is asked or when the holder is unknown to the
    /// Authentication Center.
    /// </summary>
    byte[]? PinGrant { get; set; }
}

/// <summary>
/// The countersignature of an approval statement by the Authentication Center (<see cref="Purpose"/>): it covers the same
/// data as the host's signature (<see cref="PartyApprovalStatement.GetSignedData"/>) and lives as long, from the time of
/// the statement or from the clock of the Authentication Center when it is earlier. A statement whose time is ahead of
/// this clock (more than <see cref="ClockSkew"/>) or that already expired is not countersigned.
/// </summary>
public static class ApprovalCountersignature
{
    /// <summary>
    /// The purpose of the countersignature by the Authentication Center.
    /// </summary>
    public const string Purpose = "CK.AuthCenter.PartyApproval";

    /// <summary>
    /// The tolerated advance of the time of a statement on the clock of the Authentication Center: 1 minute.
    /// </summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes( 1 );
}

/// <summary>
/// The <see cref="IPartyApprovalCountersignature"/> of a System that has an Authentication Center:
/// <list type="bullet">
///   <item>On the host, the countersignature is asked to the Authentication Center (<see cref="ICountersignApprovalCommand"/>):
///   signed here when the host is the Authentication Center, sent to it otherwise as a routed command (along the path to the
///   remote, or along its route), with the operator's proof, sealed.</item>
///   <item>On the holder, it is required when the holder has an Authentication Center, and verified with its keys (pinned
///   or anchored): an approval without it, or with an invalid one, is refused.</item>
///   <item>On the Authentication Center, the command is handled: the operator's live proof, its identity and the host.</item>
///   <item>On the host, once a holder approved the key, the routes of the statement are authorized by the Authentication
///   Center (<see cref="ApprovedAsync"/>): the same command, <see cref="ICountersignApprovalCommand.Approved"/>.</item>
/// </list>
/// A party without Authentication Center neither asks nor requires a countersignature.
/// </summary>
public sealed class AuthCenterApprovalCountersignature : IPartyApprovalCountersignature
{
    readonly PartyRoutedCommandSender _sender;

    /// <summary>
    /// Initializes a new countersignature service.
    /// </summary>
    /// <param name="sender">The sender of the routed commands.</param>
    public AuthCenterApprovalCountersignature( PartyRoutedCommandSender sender )
    {
        _sender = sender;
    }

    /// <inheritdoc />
    public async ValueTask<(bool Success, byte[]? Countersignature, byte[]? PinGrant)> CountersignAsync( IActivityMonitor monitor,
                                                                                                        IServiceProvider services,
                                                                                                        ILocalParty host,
                                                                                                        IPartyApprovalStatement statement,
                                                                                                        bool withPinGrant )
    {
        var center = host.GetFeature<CrisAuthCenter>();
        if( center == null ) return (true, null, null);
        if( center.AuthCenter == host )
        {
            // The host is the Authentication Center: the operator's request is executed here, at the Critical level.
            var signature = Sign( monitor, host, statement );
            if( signature == null ) return (false, null, null);
            return (true, signature, withPinGrant ? CreatePinGrant( monitor, host, statement ) : null);
        }
        var result = await SendAsync( monitor, services, host, center, statement, withPinGrant, approved: false ).ConfigureAwait( false );
        if( result is ICountersignApprovalResult r ) return (true, r.Countersignature, r.PinGrant);
        return (false, null, null);
    }

    /// <inheritdoc />
    public async ValueTask ApprovedAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty host, IPartyApprovalStatement statement )
    {
        var center = host.GetFeature<CrisAuthCenter>();
        if( center == null || statement.Routes.Count == 0 ) return;
        if( center.AuthCenter == host )
        {
            await AuthorizeRoutesAsync( monitor, host, statement ).ConfigureAwait( false );
            return;
        }
        if( await SendAsync( monitor, services, host, center, statement, withPinGrant: false, approved: true ).ConfigureAwait( false ) == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The routes of '{statement.PartyFullName}' are not authorized by the AuthCenter '{center.AuthCenterFullName}'." );
        }
    }

    // Sends the command to the Authentication Center. Null when it can't be sent or is refused (the reason is logged).
    async Task<ICountersignApprovalResult?> SendAsync( IActivityMonitor monitor,
                                                       IServiceProvider services,
                                                       ILocalParty host,
                                                       CrisAuthCenter center,
                                                       IPartyApprovalStatement statement,
                                                       bool withPinGrant,
                                                       bool approved )
    {
        var command = services.GetRequiredService<PocoDirectory>().Create<ICountersignApprovalCommand>( c =>
        {
            // The operator: its live proof travels with the command.
            c.ActorId = statement.OperatorActorId;
            c.Statement = statement;
            c.WithPinGrant = withPinGrant;
            c.Approved = approved;
        } );
        var what = approved ? "authorize the routes of" : "countersign the approval of";
        object? result;
        try
        {
            // Always addressed to the Authentication Center (the handler is everywhere this package is): along the path to
            // the remote, or along its route. The operator's proof travels with it, sealed.
            result = center.AuthCenter != null
                        ? await _sender.SendAlongPathAsync( monitor, services, host, command, [host.FullName.Path, center.AuthCenterFullName] ).ConfigureAwait( false )
                        : await _sender.SendAsync( monitor, services, host, command, AuthCenterFeature.RouteName, center.AuthCenterFullName ).ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to ask the AuthCenter '{center.AuthCenterFullName}' to {what} '{statement.PartyFullName}'.", ex );
            return null;
        }
        if( result is ICountersignApprovalResult r ) return r;
        var error = result is ICrisResultError e ? e.Errors.Select( m => m.Text ).Concatenate() : "refused";
        monitor.Warn( $"The AuthCenter '{center.AuthCenterFullName}' doesn't {what} '{statement.PartyFullName}': {error}" );
        return null;
    }

    /// <inheritdoc />
    public async ValueTask<bool> VerifyAsync( IActivityMonitor monitor, ILocalParty holder, IPartyApprovalStatement statement )
    {
        var center = holder.GetFeature<CrisAuthCenter>();
        if( center == null ) return true;
        if( statement.CenterCountersignature == null
            || !ApplicationSignature.TryRead( statement.CenterCountersignature, out var signature ) )
        {
            monitor.Warn( $"The approval of '{statement.PartyFullName}' has no countersignature of the AuthCenter '{center.AuthCenterFullName}'." );
            return false;
        }
        var verdict = await center.CheckWithKeyEventsAsync( monitor, ApprovalCountersignature.Purpose, PartyApprovalStatement.GetSignedData( statement ), signature ).ConfigureAwait( false );
        if( verdict != SignatureVerdict.Valid )
        {
            monitor.Warn( $"The countersignature of the approval of '{statement.PartyFullName}' by the AuthCenter '{center.AuthCenterFullName}' is invalid ({verdict})." );
            return false;
        }
        return true;
    }

    // The Authentication Center authorizes the approved party to host the routes the operator approved with it.
    static async Task AuthorizeRoutesAsync( IActivityMonitor monitor, ILocalParty center, IPartyApprovalStatement statement )
    {
        if( statement.Routes.Count == 0 ) return;
        if( center.GetFeature<AuthCenterSystemList>() is not { } list )
        {
            monitor.Warn( $"The AuthCenter '{center}' has no System list: the routes of '{statement.PartyFullName}' are not authorized." );
            return;
        }
        var updated = await list.AuthorizeAsync( monitor, statement.PartyFullName, statement.Routes ).ConfigureAwait( false );
        monitor.Info( ActivityMonitor.Tags.SecurityCritical,
                      $"'{statement.PartyFullName}' is authorized to host the route(s) '{string.Join( "', '", statement.Routes )}' with its approval, by actor #{statement.OperatorActorId}: {updated}." );
    }

    // The Authentication Center signs the same data as the host, for the same lifetime, from the time of the statement or
    // from its own clock when it is earlier: the host can't extend the window of the operator's gesture. Null when the time
    // of the statement is ahead of the clock (more than ClockSkew) or when the statement already expired.
    static byte[]? Sign( IActivityMonitor monitor, ILocalParty center, IPartyApprovalStatement statement )
    {
        var utcNow = center.ApplicationIdentityService.SystemClock.UtcNow;
        if( statement.Time > utcNow + ApprovalCountersignature.ClockSkew || statement.Time + PartyApprovalStatement.Lifetime <= utcNow )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                          $"The AuthCenter '{center}' refuses to countersign the approval of '{statement.PartyFullName}': its time {statement.Time:O} is out of the window of its clock ({utcNow:O})." );
            return null;
        }
        var from = statement.Time < utcNow ? statement.Time : utcNow;
        return center.GetRequiredFeature<ILocalKeys>()
                     .Sign( ApprovalCountersignature.Purpose,
                            PartyApprovalStatement.GetSignedData( statement ),
                            from + PartyApprovalStatement.Lifetime )
                     .Encoded.ToArray();
    }

    // The statement of an approved key: countersigned here before (the routes are authorized once the holder approved it).
    static bool IsCountersigned( IActivityMonitor monitor, ILocalParty center, IPartyApprovalStatement statement )
    {
        return statement.CenterCountersignature != null
               && ApplicationSignature.TryRead( statement.CenterCountersignature, out var signature )
               && center.GetRequiredFeature<IPartyKeys>().Check( monitor, ApprovalCountersignature.Purpose, PartyApprovalStatement.GetSignedData( statement ), signature ) == SignatureVerdict.Valid;
    }

    // The Authentication Center signs a pin grant of the holder for the approved party: the checkpoint of the holder is what
    // the Authentication Center knows of it (itself, its pin of a remote, or its anchor), never what the page says.
    static byte[]? CreatePinGrant( IActivityMonitor monitor, ILocalParty center, IPartyApprovalStatement statement )
    {
        var keys = center.GetRequiredFeature<ILocalKeys>();
        var holder = statement.HolderFullName;
        KeyCheckpoint? checkpoint;
        if( holder == center.FullName.Path )
        {
            checkpoint = KeyCheckpoint.Of( holder, keys.State.Head );
        }
        else if( center.Remotes.FirstOrDefault( r => r.FullName.Path == holder )?.GetFeature<IRemoteKeys>()?.TrustedEvent is { } pinned )
        {
            checkpoint = KeyCheckpoint.Of( holder, pinned );
        }
        else
        {
            var anchored = keys.FindAnchoredKeys( holder );
            checkpoint = anchored?.Head is { } head
                            ? KeyCheckpoint.Of( holder, head )
                            : anchored?.GetStatedCheckpoint( monitor );
        }
        if( checkpoint == null )
        {
            monitor.Warn( $"The AuthCenter '{center}' doesn't know '{holder}' (not a pinned remote, not anchored): no pin grant for '{statement.PartyFullName}', it must approve '{holder}' itself." );
            return null;
        }
        var grant = PinGrant.Create( keys, statement.PartyFullName, statement.KeyFingerprint, holder, checkpoint, center.ApplicationIdentityService.SystemClock.UtcNow );
        monitor.Info( ActivityMonitor.Tags.SecurityCritical,
                      $"The AuthCenter '{center}' grants '{statement.PartyFullName}' (key '{statement.KeyFingerprint}') the pin of '{holder}' from {checkpoint}, until {grant.Expiration:O}." );
        return grant.Encode();
    }

    /// <summary>
    /// Handles the <see cref="ICountersignApprovalCommand"/> on the Authentication Center: the operator (at the Critical
    /// level, checked by <see cref="ICommandAuthCritical"/>) must be the operator of the statement, not impersonated, and the
    /// caller party must be its host.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party.</param>
    /// <param name="authentication">The authentication of the operator.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The countersignature (and the pin grant), or null when it is refused (the reason is logged).</returns>
    [CommandHandler]
    public async Task<ICountersignApprovalResult?> HandleAsync( IActivityMonitor monitor,
                                                                ICountersignApprovalCommand command,
                                                                CurrentLocalParty current,
                                                                AuthenticationInfo authentication,
                                                                PocoDirectory pocos )
    {
        var local = current.LocalParty;
        var statement = command.Statement;
        if( local.GetFeature<CrisAuthCenter>()?.AuthCenter != local || statement == null )
        {
            monitor.Warn( $"'{local}' is asked to countersign an approval: it is not an Authentication Center." );
            return null;
        }
        string? refusal = null;
        if( authentication.IsImpersonated ) refusal = "the operator is impersonating";
        else if( authentication.ActualActor.Level < AuthLevel.Critical ) refusal = "the operator is not at the Critical level";
        else if( authentication.Actor.ActorId != statement.OperatorActorId ) refusal = $"the operator #{authentication.Actor.ActorId} is not the one of the statement (#{statement.OperatorActorId})";
        else if( authentication.CallerPartyFullName != statement.HostFullName ) refusal = $"the caller party '{authentication.CallerPartyFullName}' is not the host of the statement ('{statement.HostFullName}')";
        else if( command.Approved && !IsCountersigned( monitor, local, statement ) ) refusal = "the approved statement is not countersigned by it";
        if( refusal != null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The AuthCenter '{local}' refuses to countersign the approval of '{statement.PartyFullName}': {refusal}." );
            return null;
        }
        if( command.Approved )
        {
            // A holder approved the key: the routes of the statement are authorized.
            await AuthorizeRoutesAsync( monitor, local, statement ).ConfigureAwait( false );
            return pocos.Create<ICountersignApprovalResult>( r => r.Countersignature = statement.CenterCountersignature! );
        }
        var signature = Sign( monitor, local, statement );
        if( signature == null ) return null;
        monitor.Info( ActivityMonitor.Tags.SecurityCritical,
                      $"The AuthCenter '{local}' countersigns the approval of '{statement.PartyFullName}' (key '{statement.KeyFingerprint}') pending on '{statement.HolderFullName}', by actor #{statement.OperatorActorId} on '{statement.HostFullName}'." );
        return pocos.Create<ICountersignApprovalResult>( r =>
        {
            r.Countersignature = signature;
            r.PinGrant = command.WithPinGrant ? CreatePinGrant( monitor, local, statement ) : null;
        } );
    }
}
