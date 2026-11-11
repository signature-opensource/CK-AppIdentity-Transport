using CK.AppIdentity.AuthCenter.Enlistment;
using CK.AppIdentity.Cris;
using CK.AppIdentity.Enlistment;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Auth;
using CK.Core;
using CK.IO.AppIdentity.Enlistment;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.AuthCenter.Tests;

/// <summary>
/// The statements of the Authentication Center that make the enlistment of a party connected to nothing safer (see
/// <see cref="IPeeringAuthority"/>): "Test/$W" &gt; "Test/$Holder" &gt; "Test/$Center". The center hosts the approval page,
/// the holder is a remote of the center, W is a remote of the holder only: it anchors the center. W and the holder don't
/// trust each other ("both approval"). W initiates, or the holder does.
/// </summary>
[TestFixture]
public class PeeringAuthorityTests
{
    const int CenterPort = 37170;
    const int HolderPort = 37171;
    const int WPort = 37172;

    // The approval page: a client application with the "Enlistment" fact (the "Enlistment" route).
    public sealed class ApprovalPageFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public ApprovalPageFeatureDriver( ApplicationIdentityService s ) : base( s, true ) { }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
        {
            builder.AddClientApplication( new ClientApplicationDescription( "Admin",
                                                                            "/admin",
                                                                            ClientApplicationFacts.Create( (TransportFeatureDriver.EnlistmentFact, "app-identity/enlist") ) ) );
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

    static readonly Type[] _types = [typeof( PartyRoutedCommandSender ),
                                     typeof( IPartySealedResult ),
                                     typeof( IGetKeyEventsQCommand ),
                                     typeof( IPartyKeyEvents ),
                                     typeof( KeyEventsHandler ),
                                     typeof( AnchoredKeyDirectory ),
                                     typeof( IApprovePartyCommand ),
                                     typeof( IPartyApprovalOutcome ),
                                     typeof( IApprovePendingPartyCommand ),
                                     typeof( IPartyApprovalStatement ),
                                     typeof( IGetPendingApprovalsQCommand ),
                                     typeof( IPendingApproval ),
                                     typeof( PartyApprovalHandlers ),
                                     typeof( AuthCenterApprovalCountersignature ),
                                     typeof( ICountersignApprovalCommand ),
                                     typeof( ICountersignApprovalResult ),
                                     typeof( AuthCenterPeeringAuthority ),
                                     typeof( IGetEnlistmentUrlQCommand ),
                                     typeof( AuthCenterRoutedCommandSeal )];

    static readonly AuthenticationInfo _operator = AuthenticationInfo.CreateRestored( new ActorInfo( 3712, "Operator", AuthLevel.Critical ),
                                                                                       new ActorInfo( 3712, "Operator", AuthLevel.Critical ),
                                                                                       AuthLevel.Critical,
                                                                                       null,
                                                                                       DateTime.UtcNow );

    sealed class Chain : IAsyncDisposable
    {
        public required RunningApplication Center { get; init; }
        public required RunningApplication Holder { get; init; }
        public required RunningApplication W { get; init; }

        public async ValueTask DisposeAsync()
        {
            await W.DisposeAsync();
            await Holder.DisposeAsync();
            await Center.DisposeAsync();
        }
    }

    static async Task<Chain> StartAsync( bool anchored, bool holderInitiates = false )
    {
        var center = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: false, c =>
        {
            c["FullName"] = "Test/$Center";
            c["Local:PublicUrl"] = "https://admin.example.com";
            c["Parties:0:PartyName"] = "$Holder";
            c["Defaults:AllowFeatures"] = "AuthCenter,AuthCenterRemote";
            c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{CenterPort}";
        }, null, [.. RemoteAuthCenterTests._common, .. RemoteAuthCenterTests._centerTypes, .. _types, typeof( ApprovalPageFeatureDriver )] );
        RunningApplication? holder = null;
        try
        {
            var checkpoint = center.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().Checkpoint;
            string centerName = center.ApplicationIdentityService.FullName.Path;
            holder = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: true, c =>
            {
                c["FullName"] = "Test/$Holder";
                c["Parties:0:PartyName"] = "$Center";
                c["Parties:0:Address"] = $"tcp:127.0.0.1:{CenterPort}";
                c["Parties:0:AllowFeatures"] = "AuthCenterRemote";
                c["Parties:1:PartyName"] = "$W";
                c["Parties:1:AutoTrustKey"] = "Never";
                if( holderInitiates ) c["Parties:1:Address"] = $"tcp:127.0.0.1:{WPort}";
                else c["Parties:1:ListeningAddress:0"] = $"tcp:127.0.0.1:{HolderPort}";
            }, RunningApplication.WithHeartBeat( RemoteAuthCenterTests.RemoteServices ), [.. RemoteAuthCenterTests._common, .. RemoteAuthCenterTests._remoteTypes, .. _types] );
            var w = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: !holderInitiates, c =>
            {
                c["FullName"] = "Test/$W";
                c["Parties:0:PartyName"] = "$Holder";
                if( holderInitiates ) c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{WPort}";
                else c["Parties:0:Address"] = $"tcp:127.0.0.1:{HolderPort}";
                c["Parties:0:AutoTrustKey"] = "Never";
                if( anchored )
                {
                    c[$"Local:TrustAnchors:{centerName}"] = checkpoint.ToString();
                    c["Local:AuthCenterParty"] = centerName;
                }
            }, RunningApplication.WithHeartBeat( RemoteAuthCenterTests.RemoteServices ), [.. RemoteAuthCenterTests._common, .. _types, typeof( RemoteAuthCenterFeatureDriver ), typeof( AuthCenterProofVerifier )] );
            return new Chain { Center = center, Holder = holder, W = w };
        }
        catch
        {
            if( holder != null ) await holder.DisposeAsync();
            await center.DisposeAsync();
            throw;
        }
    }

    static async Task<T?> WaitForAsync<T>( Func<T?> get, int seconds = 40 ) where T : class
    {
        for( int i = 0; i < seconds * 10; ++i )
        {
            var v = get();
            if( v != null ) return v;
            await Task.Delay( 100 );
        }
        return null;
    }

    static PeeringIssue? IssueOf( RunningApplication app, string fullName )
        => app.ApplicationIdentityService.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().FirstOrDefault( i => i.FullName == fullName );

    // The approval page's command, handled on the center by the operator (the request is executed there).
    static async Task<IPartyApprovalOutcome[]> ApproveAsync( RunningApplication host, string party, string code )
    {
        await using var scope = host.CreateAsyncScopeServices();
        var command = host.PocoDirectory.Create<IApprovePartyCommand>( c =>
        {
            c.PartyFullName = party;
            c.Codes.Add( code );
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
    public async Task the_waiting_party_gets_an_authenticated_url_and_the_approval_on_the_page_connects_it_in_one_gesture_Async()
    {
        await using var c = await StartAsync( anchored: true );
        string wName = c.W.ApplicationIdentityService.FullName;
        string holderName = c.Holder.ApplicationIdentityService.FullName;

        // The pending approval of W reaches the approval page on the center: W and the holder must approve each other.
        var route = TransportFeatureDriver.EnlistmentRouteName;
        (await WaitForAsync( () => c.Center.ApplicationIdentityService.Description.Collected.TryGetValue( route, out var items ) && items.Length == 1 ? "reached" : null ))
            .ShouldNotBeNull( "The pending approval reached the host." );
        var handlers = c.Center.Services.GetRequiredService<PartyApprovalHandlers>();
        var pending = handlers.Handle( c.Center.PocoDirectory.Create<IGetPendingApprovalsQCommand>(), new CurrentLocalParty( c.Center.ApplicationIdentityService ), c.Center.PocoDirectory )
                              .ShouldHaveSingleItem();
        pending.PartyFullName.ShouldBe( wName );
        pending.HolderFullName.ShouldBe( holderName );
        pending.Kind.ShouldBe( "Both" );

        // (C) The holder pulled the approval page stated by the center: W receives it, verifies it with its anchor of the
        // center, and appends its own name.
        var issue = await WaitForAsync( () => IssueOf( c.W, holderName ) is { IsEnlistUrlAuthenticated: true } i ? i : null );
        issue.ShouldNotBeNull( "The enlistment URL is authenticated by the center's statement." );
        issue.Kind.ShouldBe( PeeringIssueKind.RequiresBothApproval );
        issue.EnlistUrl.ShouldBe( "https://admin.example.com/admin" + "/app-identity/enlist" + "?party=" + Uri.EscapeDataString( wName ) );

        // (B) One approval on the page: the holder pins W, the center's pin grant reaches W that pins the holder.
        var code = await WaitForAsync( () => IssueOf( c.W, holderName )?.ApprovalCode );
        code.ShouldNotBeNull();
        (await ApproveAsync( c.Center, wName, code )).ShouldHaveSingleItem().Status.ShouldBe( PartyApprovalStatus.Approved );
        (await WaitForAsync( () => c.W.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected ? "connected" : null ))
            .ShouldNotBeNull( "W pinned the holder from the grant: they connect, nothing was done on W." );
        c.W.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<IRemoteKeys>().TrustedEvent.ShouldNotBeNull();
    }

    [Test]
    public async Task when_the_holder_initiates_the_url_and_the_grant_travel_in_its_messages_Async()
    {
        await using var c = await StartAsync( anchored: true, holderInitiates: true );
        string wName = c.W.ApplicationIdentityService.FullName;
        string holderName = c.Holder.ApplicationIdentityService.FullName;

        // W listens: it receives the approval page in the holder's reply to its rejection (RequiredEnlistUrl).
        var issue = await WaitForAsync( () => IssueOf( c.W, holderName ) is { IsEnlistUrlAuthenticated: true } i ? i : null );
        issue.ShouldNotBeNull( "The enlistment URL is authenticated by the center's statement." );
        issue.EnlistUrl.ShouldBe( "https://admin.example.com/admin" + "/app-identity/enlist" + "?party=" + Uri.EscapeDataString( wName ) );

        // The holder holds the pending approval of W: the grant travels in its next initial message, W pins it in the
        // same attempt.
        var route = TransportFeatureDriver.EnlistmentRouteName;
        (await WaitForAsync( () => c.Center.ApplicationIdentityService.Description.Collected.TryGetValue( route, out var items ) && items.Length == 1 ? "reached" : null ))
            .ShouldNotBeNull( "The pending approval reached the host." );
        var code = await WaitForAsync( () => IssueOf( c.Holder, wName )?.ApprovalCode );
        code.ShouldNotBeNull();
        (await ApproveAsync( c.Center, wName, code )).ShouldHaveSingleItem().Status.ShouldBe( PartyApprovalStatus.Approved );
        (await WaitForAsync( () => c.W.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected ? "connected" : null ))
            .ShouldNotBeNull( "W pinned the holder from the grant of its initial message." );
    }

    [Test]
    public async Task a_grant_that_is_not_the_one_of_the_authority_of_the_waiting_party_is_refused_Async()
    {
        await using var c = await StartAsync( anchored: true );
        string wName = c.W.ApplicationIdentityService.FullName;
        string holderName = c.Holder.ApplicationIdentityService.FullName;
        var wKeys = c.W.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();
        var holderKeys = c.Holder.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();
        var centerKeys = c.Center.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();
        var wFingerprint = new RemoteIdentityKeyData( wKeys.State.Head ).GetFingerprint();
        var holderCheckpoint = holderKeys.Checkpoint;

        // The holder approves W itself (with the code): W must now approve the holder.
        var code = await WaitForAsync( () => IssueOf( c.W, holderName )?.ApprovalCode );
        code.ShouldNotBeNull();
        var onHolder = (await WaitForAsync( () => IssueOf( c.Holder, wName ) )).ShouldNotBeNull();
        onHolder.TryApprove( TestHelper.Monitor, code, onHolder.RemoteKeyFingerprintForApproval!, out _ ).ShouldBeTrue();
        (await WaitForAsync( () => IssueOf( c.W, holderName ) is { Kind: PeeringIssueKind.RequiresLocalApproval } i ? i : null )).ShouldNotBeNull();
        var wOnHolder = c.Holder.ApplicationIdentityService.Remotes.Single( r => r.FullName.Path == wName ).GetRequiredFeature<TransportFeature>();
        var holderOnW = c.W.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<IRemoteKeys>();

        async Task RefusedAsync( AnchoredStatement grant, string reason )
        {
            wOnHolder.OfferPinGrant( TestHelper.Monitor, grant ).ShouldBeTrue();
            // W retries every 5 seconds: two attempts.
            await Task.Delay( 11_000 );
            holderOnW.TrustedEvent.ShouldBeNull( reason );
        }
        // Signed by the holder itself: not the authority of W.
        await RefusedAsync( PinGrant.Create( holderKeys, wName, wFingerprint, holderName, holderCheckpoint, DateTime.UtcNow ), "Not signed by the center." );
        // Signed by the center, for another key of W.
        await RefusedAsync( PinGrant.Create( centerKeys, wName, "AAAA-BBBB", holderName, holderCheckpoint, DateTime.UtcNow ), "Not the key of W." );
        // Signed by the center, but the checkpoint is not the holder's log.
        await RefusedAsync( PinGrant.Create( centerKeys, wName, wFingerprint, holderName, centerKeys.Checkpoint, DateTime.UtcNow ), "Not the log of the holder." );

        // The center's grant: W pins the holder, they connect.
        wOnHolder.OfferPinGrant( TestHelper.Monitor, PinGrant.Create( centerKeys, wName, wFingerprint, holderName, holderCheckpoint, DateTime.UtcNow ) ).ShouldBeTrue();
        (await WaitForAsync( () => c.W.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected ? "connected" : null ))
            .ShouldNotBeNull();
    }

    [Test]
    public async Task without_the_anchor_the_url_is_not_authenticated_and_the_waiting_party_still_waits_Async()
    {
        await using var c = await StartAsync( anchored: false );
        string wName = c.W.ApplicationIdentityService.FullName;
        string holderName = c.Holder.ApplicationIdentityService.FullName;

        // The URL is the center's statement, but W can't verify it: it is read, not authenticated.
        var issue = await WaitForAsync( () => IssueOf( c.W, holderName ) is { EnlistUrl: not null } i ? i : null );
        issue.ShouldNotBeNull();
        issue.IsEnlistUrlAuthenticated.ShouldBeFalse();

        // The approval on the page approves W on the holder only: W must still approve the holder (CKey, later).
        var code = await WaitForAsync( () => IssueOf( c.W, holderName )?.ApprovalCode );
        code.ShouldNotBeNull();
        (await ApproveAsync( c.Center, wName, code )).ShouldHaveSingleItem().Status.ShouldBe( PartyApprovalStatus.Approved );
        (await WaitForAsync( () => IssueOf( c.W, holderName ) is { Kind: PeeringIssueKind.RequiresLocalApproval } i ? i : null ))
            .ShouldNotBeNull( "The holder trusts W, W doesn't trust the holder." );
        c.W.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<IRemoteKeys>().TrustedEvent.ShouldBeNull();
    }
}
