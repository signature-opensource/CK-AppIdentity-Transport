using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using CK.IO.Authentication.Weak;
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
/// An Authentication Center reached without a channel: "Test/$A" &gt; "Test/$Hop" &gt; "Test/$Center". The hop is a remote
/// of the center (it opens the sessions), A is a remote of the hop only: it anchors the center and designates it by its
/// full name ("Local:AuthCenterParty").
/// </summary>
[TestFixture]
public class AnchoredAuthCenterTests
{
    const int CenterPort = 37148;
    const int HopPort = 37149;

    static readonly Type[] _routing = [typeof( PartyRoutedCommandSender ),
                                       typeof( IPartySealedResult ),
                                       typeof( IGetKeyEventsQCommand ),
                                       typeof( IPartyKeyEvents ),
                                       typeof( KeyEventsHandler ),
                                       typeof( AnchoredKeyDirectory ),
                                       typeof( IVerifyRoutedProofQCommand ),
                                       typeof( IAuthCenterProofStatement )];

    sealed class Chain : IAsyncDisposable
    {
        public required RunningApplication Center { get; init; }
        public required RunningApplication Hop { get; init; }
        public required RunningApplication A { get; init; }

        public string CenterName => Center.ApplicationIdentityService.FullName.Path;
        public string HopName => Hop.ApplicationIdentityService.FullName.Path;
        public string AName => A.ApplicationIdentityService.FullName.Path;
        public AuthCenterApp.Browser Browser => Hop.Services.GetRequiredService<AuthCenterApp.Browser>();

        public async ValueTask DisposeAsync()
        {
            await A.DisposeAsync();
            await Hop.DisposeAsync();
            await Center.DisposeAsync();
        }

        // A request of the browser to the hop's endpoint: the hop opens the sessions.
        public async Task<object?> RequestAsync( Func<PocoDirectory, IAbstractCommand> create )
        {
            await using var scope = Hop.CreateAsyncScopeServices();
            var services = scope.ServiceProvider;
            var command = create( services.GetRequiredService<PocoDirectory>() );
            var result = (await services.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( services, command )).Result;
            if( result is ISessionResult { Token: { } token } )
            {
                var center = Hop.ApplicationIdentityService.GetRequiredFeature<CrisAuthCenter>();
                Browser.Current = (await center.ReadTokenAsync( TestHelper.Monitor, token, DateTime.UtcNow )).ShouldNotBeNull().Info;
                Browser.Token = token;
            }
            return result;
        }
    }

    static async Task<Chain> StartAsync( Func<KeyCheckpoint, string>? anchor = null )
    {
        var center = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: false, c =>
        {
            c["FullName"] = "Test/$Center";
            c["Parties:0:PartyName"] = "$Hop";
            c["Defaults:AllowFeatures"] = "AuthCenter,AuthCenterRemote";
            c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{CenterPort}";
        }, null, [.. RemoteAuthCenterTests._common, .. RemoteAuthCenterTests._centerTypes, .. _routing, typeof( VerifyRoutedProofHandler )] );
        try
        {
            var checkpoint = center.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().Checkpoint;
            string centerName = center.ApplicationIdentityService.FullName.Path;
            var hop = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: true, c =>
            {
                c["FullName"] = "Test/$Hop";
                c["Parties:0:PartyName"] = "$Center";
                c["Parties:0:Address"] = $"tcp:127.0.0.1:{CenterPort}";
                c["Parties:0:AllowFeatures"] = "AuthCenterRemote";
                c["Parties:1:PartyName"] = "$A";
                c["Parties:1:AutoTrustKey"] = "Once";
                c["Parties:1:ListeningAddress:0"] = $"tcp:127.0.0.1:{HopPort}";
            }, RemoteAuthCenterTests.RemoteServices, [.. RemoteAuthCenterTests._common, .. RemoteAuthCenterTests._remoteTypes, .. _routing] );
            var a = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: true, c =>
            {
                c["FullName"] = "Test/$A";
                c["Parties:0:PartyName"] = "$Hop";
                c["Parties:0:Address"] = $"tcp:127.0.0.1:{HopPort}";
                c[$"Local:TrustAnchors:{centerName}"] = anchor?.Invoke( checkpoint ) ?? checkpoint.ToString();
                c["Local:AuthCenterParty"] = centerName;
            }, RemoteAuthCenterTests.RemoteServices, [.. RemoteAuthCenterTests._common, .. _routing, typeof( RemoteAuthCenterFeatureDriver ), typeof( AuthCenterProofVerifier )] );
            var chain = new Chain { Center = center, Hop = hop, A = a };
            for( int i = 0; i < 100 && !a.ApplicationIdentityService.Description.Routes.ContainsKey( AuthCenterFeature.RouteName ); ++i ) await Task.Delay( 100 );
            a.ApplicationIdentityService.Description.Routes.ShouldContainKey( AuthCenterFeature.RouteName, "The route of the center reaches A through the hop." );
            return chain;
        }
        catch
        {
            await center.DisposeAsync();
            throw;
        }
    }

    [Test]
    public async Task a_party_without_channel_reads_the_tokens_and_checks_the_proofs_with_the_anchored_center_Async()
    {
        await using var c = await StartAsync();
        var a = c.A.ApplicationIdentityService;
        a.Remotes.ShouldNotContain( r => r.FullName.Path == c.CenterName, "No channel from A to the center." );
        var aCenter = a.GetRequiredFeature<CrisAuthCenter>();
        aCenter.AuthCenter.ShouldBeNull();
        aCenter.AuthCenterFullName.ShouldBe( c.CenterName );
        a.GetRequiredFeature<IAuthCenterProofChecker>().ShouldBeOfType<AnchoredAuthCenter>();

        (await c.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( l => l.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = c.Browser.Token.ShouldNotBeNull();
        var binding = c.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;

        // The token is read with the keys of the center, fetched along its route and verified from the anchor.
        (await aCenter.ReadTokenAsync( TestHelper.Monitor, token, DateTime.UtcNow )).ShouldNotBeNull().Info.UnsafeActor.ActorName.ShouldBe( "Albert" );

        var verifier = new AuthCenterProofVerifier();
        var lastHop = a.Remotes.Single();
        using var scope = c.A.CreateScopeServices();
        var hopKeys = c.Hop.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();
        byte[] command = [1, 2, 3];
        IAuthenticationCallEnvelope Sealed()
        {
            var e = RemoteAuthCenterTests.Proof( c.A, token, binding );
            (e.RoutedSeal, e.RoutedSignature) = RoutedCommandSeal.Create( hopKeys, c.AName, token, command, DateTime.UtcNow );
            return e;
        }

        // Directly from the session party: read here, at the Critical level.
        (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, null, RemoteAuthCenterTests.Proof( c.A, token, binding ) ))
            .ShouldNotBeNull().ActualActor.Level.ShouldBe( AuthLevel.Critical );
        // Routed by the session party: the center checks the seal and the session, its signed statement is verified here.
        (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, RemoteAuthCenterTests.Routed( c.A, c.HopName, command ), Sealed() ))
            .ShouldNotBeNull().ActualActor.Level.ShouldBe( AuthLevel.Critical );

        // After a logout, the routed proof is refused at once (the center is asked); the direct one is still read here
        // (the liveness lag accepted without a channel).
        await c.RequestAsync( pocos => pocos.Create<ILogoutSessionCommand>() );
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, RemoteAuthCenterTests.Routed( c.A, c.HopName, command ), Sealed() )).ShouldBeNull();
            logs.ShouldContain( $"The AuthCenter '{c.CenterName}' refused the user's proof routed to '{c.AName}' (its session or its seal)." );
        }
        (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, null, RemoteAuthCenterTests.Proof( c.A, token, binding ) )).ShouldNotBeNull();
    }

    [Test]
    public async Task a_party_without_channel_gets_the_encryption_keys_from_the_center_Async()
    {
        await using var c = await StartAsync();
        var directory = c.A.ApplicationIdentityService.GetRequiredFeature<IPartyEncryptionKeyDirectory>();
        var utcNow = DateTime.UtcNow;
        var centerKey = (await directory.GetPartyEncryptionKeyAsync( TestHelper.Monitor, c.CenterName )).ShouldNotBeNull();
        centerKey.PublicKey.ShouldBe( c.Center.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().GetEncryptionKey( utcNow ).PublicKey.ToArray() );
        // The hop publishes its key in its description: the center vouches for it.
        for( int i = 0; i < 100 && c.Center.ApplicationIdentityService.Remotes.Single().Description.EncryptionKey == null; ++i ) await Task.Delay( 100 );
        var hopKey = (await directory.GetPartyEncryptionKeyAsync( TestHelper.Monitor, c.HopName )).ShouldNotBeNull();
        hopKey.PublicKey.ShouldBe( c.Hop.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().GetEncryptionKey( utcNow ).PublicKey.ToArray() );
        (await directory.GetPartyEncryptionKeyAsync( TestHelper.Monitor, "Test/$Unknown/#Dev" )).ShouldBeNull();
    }

    [Test]
    public async Task with_a_wrong_anchor_the_tokens_of_the_center_are_refused_Async()
    {
        await using var c = await StartAsync( cp => $"{cp.Seq}:{new string( '0', 64 )}" );
        (await c.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( l => l.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = c.Browser.Token.ShouldNotBeNull();
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await c.A.ApplicationIdentityService.GetRequiredFeature<CrisAuthCenter>().ReadTokenAsync( TestHelper.Monitor, token, DateTime.UtcNow )).ShouldBeNull();
            logs.ShouldContain( l => l.StartsWith( $"The key events received for '{c.CenterName}' don't match its trust anchor" ) );
        }
    }
}
