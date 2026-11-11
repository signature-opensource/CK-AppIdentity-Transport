using CK.AppIdentity.AuthCenter.Enlistment;
using CK.AppIdentity.Cris;
using CK.AppIdentity.Enlistment;
using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.IO.AppIdentity.Enlistment;
using CK.IO.Authentication.Weak;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
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
        IPartyApprovalStatement Statement( int op ) => p.Remote.PocoDirectory.Create<IPartyApprovalStatement>( s =>
        {
            s.PartyFullName = "Test/$Waiting/#Dev";
            s.KeyFingerprint = "ABCD-EFGH";
            s.HolderFullName = host.FullName;
            s.HostFullName = host.FullName;
            s.OperatorActorId = op;
            s.Time = DateTime.UtcNow;
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
    }
}
