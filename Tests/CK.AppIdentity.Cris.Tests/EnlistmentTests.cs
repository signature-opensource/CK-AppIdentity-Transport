using CK.AppIdentity.Enlistment;
using CK.AppIdentity.TransportLayer;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Enlistment;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The approval of a pending party (CK.AppIdentity.Enlistment): "Test/$Sender" (A) hosts the approval page,
/// "Test/$Listener" (B) is connected to it and holds the pending approval of "Test/$D", an unknown key.
/// </summary>
[TestFixture]
public class EnlistmentTests
{
    // What the AuthenticationReceptionHandler does for an anonymous command: the caller party is the origin of the route.
    public sealed class CallerPartyReceptionHandler : ICrisChannelReceptionHandler
    {
        public ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureAsync( IActivityMonitor monitor,
                                                                                           IServiceProvider services,
                                                                                           CrisCallerParty caller,
                                                                                           IAbstractCommand command,
                                                                                           ICrisCallEnvelope envelope )
        {
            var hub = services.GetRequiredService<AmbientServiceHub>().CleanClone();
            hub.Override( AuthenticationInfo.None.WithCallerParty( caller.FullName ) );
            return ValueTask.FromResult<(ICrisResultError?, AmbientServiceHub?)>( (null, hub) );
        }
    }

    static readonly Type[] _common = [typeof( AuthenticationInfo ),
                                      typeof( IPartyRoutedCommand ),
                                      typeof( PartyRoutedCommandSender ),
                                      typeof( CallerPartyReceptionHandler ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver ),
                                      typeof( IPartySealedResult ),
                                      typeof( IApprovePartyCommand ),
                                      typeof( IPartyApprovalOutcome ),
                                      typeof( IApprovePendingPartyCommand ),
                                      typeof( IPartyApprovalStatement ),
                                      typeof( IGetPendingApprovalsQCommand ),
                                      typeof( IPendingApproval ),
                                      typeof( PartyApprovalHandlers )];

    static readonly AuthenticationInfo _operator = AuthenticationInfo.CreateRestored( new ActorInfo( 3712, "Operator", AuthLevel.Critical ),
                                                                                       new ActorInfo( 3712, "Operator", AuthLevel.Critical ),
                                                                                       AuthLevel.Critical,
                                                                                       null,
                                                                                       DateTime.UtcNow );

    static async Task<T?> WaitForAsync<T>( Func<T?> get ) where T : class
    {
        for( int i = 0; i < 300; ++i )
        {
            var v = get();
            if( v != null ) return v;
            await Task.Delay( 100 );
        }
        return null;
    }

    // The approval page's command, handled on A by the operator.
    static async Task<IPartyApprovalOutcome[]> ApproveAsync( RunningApplication host, string party, params string[] codes )
    {
        await using var scope = host.CreateAsyncScopeServices();
        var command = host.PocoDirectory.Create<IApprovePartyCommand>( c =>
        {
            c.PartyFullName = party;
            c.Codes.AddRange( codes );
        } );
        var outcomes = await host.Services.GetRequiredService<PartyApprovalHandlers>()
                                          .HandleAsync( TestHelper.Monitor,
                                                        command,
                                                        new CurrentLocalParty( host.ApplicationIdentityService ),
                                                        _operator,
                                                        scope.ServiceProvider,
                                                        host.PocoDirectory );
        return outcomes.ToArray();
    }

    [Test]
    public async Task an_operator_approves_a_pending_party_with_its_code_on_the_approval_page_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         c => c["Local:PublicUrl"] = "https://admin.example.com",
                                                                         [.. _common, typeof( RouteTests.ApprovalPageFeatureDriver )],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$D";
                                                                             c["Parties:1:AutoTrustKey"] = "Never";
                                                                         },
                                                                         listenerTypes: _common );
        var (a, b) = pair;
        (await a.CrisChannel.WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        var route = TransportFeatureDriver.EnlistmentRouteName;

        // D trusts B on first contact, B doesn't trust D: B must approve D's key.
        await using var d = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                  isSender: true,
                                                                  c => c["FullName"] = "Test/$D",
                                                                  RunningApplication.WithHeartBeat() );
        string dName = d.ApplicationIdentityService.FullName;
        (await WaitForAsync( () => a.ApplicationIdentityService.Description.Collected.TryGetValue( route, out var items ) && items.Length == 1 ? "reached" : null ))
            .ShouldNotBeNull( "The pending approval reached the host." );

        // The approval page lists the pending approval: D waits on B (the host doesn't need to follow a link).
        var handlers = a.Services.GetRequiredService<PartyApprovalHandlers>();
        var aLocal = new CurrentLocalParty( a.ApplicationIdentityService );
        var pending = handlers.Handle( a.PocoDirectory.Create<IGetPendingApprovalsQCommand>(), aLocal, a.PocoDirectory ).ShouldHaveSingleItem();
        pending.PartyFullName.ShouldBe( dName );
        pending.HolderFullName.ShouldBe( bName );
        pending.Kind.ShouldBe( "Local" );
        var bIssue = b.ApplicationIdentityService.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().Single( i => i.FullName == dName );
        pending.KeyFingerprint.ShouldBe( bIssue.RemoteKeyFingerprintForApproval );
        pending.Since.ShouldBe( bIssue.ApprovalPendingSince!.Value );

        // The code read on D (the attempts exchange it).
        var code = await WaitForAsync( () => d.ApplicationIdentityService.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().FirstOrDefault()?.ApprovalCode );
        code.ShouldNotBeNull();
        var wrong = code == "1234-5678" ? "8765-4321" : "1234-5678";

        // A wrong code.
        var outcome = (await ApproveAsync( a, dName, wrong )).ShouldHaveSingleItem();
        outcome.HolderFullName.ShouldBe( bName );
        outcome.Status.ShouldBe( PartyApprovalStatus.CodeMismatch );
        // A party nobody waits for.
        (await ApproveAsync( a, "Test/$Nobody", code )).ShouldBeEmpty();

        // Impersonation is refused.
        var impersonated = AuthenticationInfo.CreateRestored( new ActorInfo( 3712, "Operator", AuthLevel.Critical ),
                                                              new ActorInfo( 42, "Other", AuthLevel.Critical ),
                                                              AuthLevel.Critical,
                                                              null,
                                                              DateTime.UtcNow );
        await using var aScope = a.CreateAsyncScopeServices();
        var culture = aScope.ServiceProvider.GetRequiredService<CurrentCultureInfo>();
        var collector = new UserMessageCollector( culture );
        a.Services.GetRequiredService<PartyApprovalHandlers>().Validate( collector, a.PocoDirectory.Create<IApprovePartyCommand>(), impersonated );
        collector.ErrorCount.ShouldBe( 1 );
        collector = new UserMessageCollector( culture );
        a.Services.GetRequiredService<PartyApprovalHandlers>().Validate( collector, a.PocoDirectory.Create<IApprovePartyCommand>(), _operator );
        collector.ErrorCount.ShouldBe( 0 );

        // On the holder: only from the host of its route, only with the host's valid signature (A is a direct remote).
        var fingerprint = b.ApplicationIdentityService.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().Single( i => i.FullName == dName ).RemoteKeyFingerprintForApproval!;
        IApprovePendingPartyCommand Forged() => b.PocoDirectory.Create<IApprovePendingPartyCommand>( c =>
        {
            c.Statement = b.PocoDirectory.Create<IPartyApprovalStatement>( s =>
            {
                s.PartyFullName = dName;
                s.KeyFingerprint = fingerprint;
                s.HolderFullName = bName;
                s.HostFullName = aName;
                s.OperatorActorId = 3712;
                s.Time = DateTime.UtcNow;
                s.HostSignature = [1, 2, 3];
            } );
            c.Codes.Add( code );
        } );
        var holder = b.Services.GetRequiredService<PartyApprovalHandlers>();
        var bLocal = new CurrentLocalParty( b.ApplicationIdentityService );
        (await holder.HandleAsync( TestHelper.Monitor, Forged(), bLocal, AuthenticationInfo.None.WithCallerParty( "Test/$Other" ) ))
              .ShouldBe( PartyApprovalStatus.Refused, "Not the host of the route." );
        (await holder.HandleAsync( TestHelper.Monitor, Forged(), bLocal, AuthenticationInfo.None ))
              .ShouldBe( PartyApprovalStatus.Refused, "No caller party." );
        (await holder.HandleAsync( TestHelper.Monitor, Forged(), bLocal, AuthenticationInfo.None.WithCallerParty( aName ) ))
              .ShouldBe( PartyApprovalStatus.Refused, "The signature of the host is invalid." );

        // The right code among others: approved, D connects, the pending approval disappears.
        outcome = (await ApproveAsync( a, dName, wrong, code )).ShouldHaveSingleItem();
        outcome.Status.ShouldBe( PartyApprovalStatus.Approved );
        (await WaitForAsync( () => d.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected ? "connected" : null ))
            .ShouldNotBeNull( "D's key is trusted by B: they connect." );
        (await WaitForAsync( () => a.ApplicationIdentityService.Description.Collected.Count == 0 ? "gone" : null )).ShouldNotBeNull();
        (await ApproveAsync( a, dName, code )).ShouldBeEmpty( "Nothing to approve anymore." );
        handlers.Handle( a.PocoDirectory.Create<IGetPendingApprovalsQCommand>(), aLocal, a.PocoDirectory ).ShouldBeEmpty();
    }
}
