using CK.AppIdentity.AuthCenter.Enlistment;
using CK.AppIdentity.Cris;
using CK.AppIdentity.Enlistment;
using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.IO.AppIdentity.Enlistment;
using CK.IO.AuthCenter;
using CK.IO.Authentication.Weak;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.AuthCenter.Tests;

/// <summary>
/// The countersignature of an approval statement by the Authentication Center: the remote of the AuthCenter is the host of
/// the approval page (its operator is signed in there) and the holder.
/// </summary>
[TestFixture]
public class ApprovalCountersignatureTests
{
    static readonly Type[] _types = [typeof( AuthCenterApprovalCountersignature ),
                                     typeof( ICountersignApprovalCommand ),
                                     typeof( ICountersignApprovalResult ),
                                     typeof( IPartyApprovalStatement ),
                                     typeof( PartyRoutedCommandSender ),
                                     typeof( IPartySealedResult ),
                                     typeof( AuthCenterRoutedCommandSeal ),
                                     typeof( AuthCenterProofVerifier )];

    [Test]
    public async Task the_AuthCenter_countersigns_the_approval_of_the_operator_and_the_holder_requires_it_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: _types );
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var host = p.Remote.ApplicationIdentityService;
        int operatorId = p.Browser.Current.Actor.ActorId;
        IPartyApprovalStatement Statement( int op, DateTime? time = null ) => p.Remote.PocoDirectory.Create<IPartyApprovalStatement>( s =>
        {
            s.PartyFullName = "Test/$Waiting/#Dev";
            s.KeyFingerprint = "ABCD-EFGH";
            s.HolderFullName = host.FullName;
            s.HostFullName = host.FullName;
            s.OperatorActorId = op;
            s.Time = time ?? DateTime.UtcNow;
            s.HostSignature = host.GetRequiredFeature<ILocalKeys>().Sign( PartyApprovalStatement.Purpose,
                                                                         PartyApprovalStatement.GetSignedData( s ),
                                                                         s.Time + PartyApprovalStatement.Lifetime ).Encoded.ToArray();
        } );

        // In the operator's request: the AuthCenter checks its live proof and countersigns.
        await using var scope = p.Remote.CreateAsyncScopeServices();
        var countersignature = scope.ServiceProvider.GetRequiredService<IPartyApprovalCountersignature>();
        var statement = Statement( operatorId );
        var (success, signature, grant) = await countersignature.CountersignAsync( TestHelper.Monitor, scope.ServiceProvider, host, statement, withPinGrant: false );
        grant.ShouldBeNull();
        success.ShouldBeTrue();
        statement.CenterCountersignature = signature.ShouldNotBeNull();
        (await countersignature.VerifyAsync( TestHelper.Monitor, host, statement )).ShouldBeTrue();

        // The holder has an AuthCenter: a statement that is not the countersigned one, or without countersignature, is refused.
        statement.KeyFingerprint = "IJKL-MNOP";
        (await countersignature.VerifyAsync( TestHelper.Monitor, host, statement )).ShouldBeFalse();
        var missing = Statement( operatorId );
        (await countersignature.VerifyAsync( TestHelper.Monitor, host, missing )).ShouldBeFalse();

        // The AuthCenter refuses to countersign for another operator than the one of the request.
        (success, signature, _) = await countersignature.CountersignAsync( TestHelper.Monitor, scope.ServiceProvider, host, Statement( operatorId + 1 ), withPinGrant: false );
        success.ShouldBeFalse();
        signature.ShouldBeNull();

        // The lifetime of the countersignature comes from the clock of the AuthCenter: a statement dated in the future
        // (a host that would extend the window of the operator's gesture) is refused, an old one expires with its time.
        (await countersignature.CountersignAsync( TestHelper.Monitor, scope.ServiceProvider, host, Statement( operatorId, DateTime.UtcNow.AddDays( 6 ) ), withPinGrant: false ))
            .Success.ShouldBeFalse();
        var old = Statement( operatorId, DateTime.UtcNow.AddMinutes( -5 ) );
        (success, signature, _) = await countersignature.CountersignAsync( TestHelper.Monitor, scope.ServiceProvider, host, old, withPinGrant: false );
        success.ShouldBeTrue();
        ApplicationSignature.TryRead( signature, out var oldSignature ).ShouldBeTrue();
        oldSignature.Expiration.ShouldBeLessThanOrEqualTo( old.Time + PartyApprovalStatement.Lifetime );
    }

    [Test]
    public async Task without_the_countersignature_an_application_that_has_an_AuthCenter_refuses_every_approval_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: [.. _types, typeof( IApprovePendingPartyCommand )] );
        var holder = p.Remote.ApplicationIdentityService;
        var handlers = new PartyApprovalHandlers( p.Remote.Services.GetRequiredService<PartyRoutedCommandSender>(), countersignature: null, proofVerifier: new AuthCenterProofVerifier() );
        var command = p.Remote.PocoDirectory.Create<IApprovePendingPartyCommand>( a =>
        {
            a.Statement = p.Remote.PocoDirectory.Create<IPartyApprovalStatement>( s =>
            {
                s.PartyFullName = "Test/$Waiting/#Dev";
                s.KeyFingerprint = "ABCD-EFGH";
                s.HolderFullName = holder.FullName;
                s.HostFullName = holder.FullName;
                s.Time = DateTime.UtcNow;
            } );
        } );
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await handlers.HandleAsync( TestHelper.Monitor, command, new CurrentLocalParty( holder ), p.Browser.Current ))
                .ShouldBe( PartyApprovalStatus.Refused );
            logs.ShouldContain( l => l.Contains( "not the countersignature of the approvals (CK.AppIdentity.AuthCenter.Enlistment)" ) );
        }
    }

    static async Task<bool> WaitForAsync( Func<bool> condition )
    {
        for( int i = 0; i < 100; ++i )
        {
            if( condition() ) return true;
            await Task.Delay( 100 );
        }
        return false;
    }

    [Test]
    public async Task the_AuthCenter_authorizes_route_hosts_and_its_remotes_follow_Async()
    {
        await using var p = await RemoteAuthCenterTests.StartAsync( extraTypes: [.. _types,
                                                                                 typeof( IAuthorizeRouteHostCommand ),
                                                                                 typeof( IRemoveRouteHostCommand ),
                                                                                 typeof( ISystemListCommand ),
                                                                                 typeof( IGetSystemListQCommand ),
                                                                                 typeof( SystemListHandler )] );
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var center = p.Center.ApplicationIdentityService;
        var host = p.Remote.ApplicationIdentityService;
        var remoteHosts = host.GetRequiredFeature<AuthCenterSystemList>();
        // Before any list, only the "AuthCenter" route of the center is authorized.
        remoteHosts.RouteHosts.Find( AuthCenterFeature.RouteName, center.FullName ).ShouldNotBeNull();
        remoteHosts.RouteHosts.Find( "MailSender", "Test/$Mail1/#Dev" ).ShouldBeNull();

        // Two hosts for one name, authorized by the operator (Critical commands, handled by the center): the remote follows.
        var handler = new RevokePartyHandler();
        foreach( var mail in new[] { "Test/$Mail1/#Dev", "Test/$Mail2/#Dev" } )
        {
            var authorize = p.Center.PocoDirectory.Create<IAuthorizeRouteHostCommand>( c => { c.RouteName = "MailSender"; c.HostFullName = mail; } );
            (await handler.HandleAsync( TestHelper.Monitor, authorize, new CurrentLocalParty( center ) )).ShouldNotBeNull();
        }
        (await WaitForAsync( () => remoteHosts.RouteHosts.Entries.Count( e => e.RouteName == "MailSender" ) == 2 )).ShouldBeTrue( "Relayed to the remote." );
        remoteHosts.RouteHosts.Find( "MailSender", "Test/$Mail2/#Dev" ).ShouldNotBeNull().Target.ShouldBeNull();

        // Removed: the remote follows.
        var remove = p.Center.PocoDirectory.Create<IRemoveRouteHostCommand>( c => { c.RouteName = "MailSender"; c.HostFullName = "Test/$Mail1/#Dev"; } );
        (await handler.HandleAsync( TestHelper.Monitor, remove, new CurrentLocalParty( center ) )).ShouldNotBeNull();
        (await WaitForAsync( () => remoteHosts.RouteHosts.Find( "MailSender", "Test/$Mail1/#Dev" ) == null )).ShouldBeTrue();
        // The "AuthCenter" route can't be authorized: it is implicit.
        var implicitOne = p.Center.PocoDirectory.Create<IAuthorizeRouteHostCommand>( c => { c.RouteName = AuthCenterFeature.RouteName; c.HostFullName = "Test/$Mail1/#Dev"; } );
        (await handler.HandleAsync( TestHelper.Monitor, implicitOne, new CurrentLocalParty( center ) )).ShouldBeNull();

        // An approval authorizes the routes the operator approved with it, when the center countersigns it.
        int operatorId = p.Browser.Current.Actor.ActorId;
        var statement = p.Remote.PocoDirectory.Create<IPartyApprovalStatement>( s =>
        {
            s.PartyFullName = "Test/$Waiting/#Dev";
            s.KeyFingerprint = "ABCD-EFGH";
            s.HolderFullName = host.FullName;
            s.HostFullName = host.FullName;
            s.OperatorActorId = operatorId;
            s.Time = DateTime.UtcNow;
            s.Routes.Add( "MailSender" );
            s.HostSignature = host.GetRequiredFeature<ILocalKeys>().Sign( PartyApprovalStatement.Purpose,
                                                                         PartyApprovalStatement.GetSignedData( s ),
                                                                         s.Time + PartyApprovalStatement.Lifetime ).Encoded.ToArray();
        } );
        await using var scope = p.Remote.CreateAsyncScopeServices();
        var countersignature = scope.ServiceProvider.GetRequiredService<IPartyApprovalCountersignature>();
        var (success, signature, _) = await countersignature.CountersignAsync( TestHelper.Monitor, scope.ServiceProvider, host, statement, withPinGrant: false );
        success.ShouldBeTrue();
        // Nothing is authorized before a holder approved the key.
        center.GetRequiredFeature<AuthCenterSystemList>().RouteHosts.Find( "MailSender", "Test/$Waiting/#Dev" ).ShouldBeNull();
        // Not countersigned by the center: refused.
        await countersignature.ApprovedAsync( TestHelper.Monitor, scope.ServiceProvider, host, statement );
        center.GetRequiredFeature<AuthCenterSystemList>().RouteHosts.Find( "MailSender", "Test/$Waiting/#Dev" ).ShouldBeNull();
        statement.CenterCountersignature = signature;
        await countersignature.ApprovedAsync( TestHelper.Monitor, scope.ServiceProvider, host, statement );
        center.GetRequiredFeature<AuthCenterSystemList>().RouteHosts.Find( "MailSender", "Test/$Waiting/#Dev" ).ShouldNotBeNull();
        (await WaitForAsync( () => remoteHosts.RouteHosts.Find( "MailSender", "Test/$Waiting/#Dev" ) != null )).ShouldBeTrue();
    }
}
