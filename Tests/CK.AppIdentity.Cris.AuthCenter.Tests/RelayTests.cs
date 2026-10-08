using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using CK.IO.Authentication.Basic;
using CK.IO.Authentication.Weak;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// A front (the "Sender", without any login provider) relays the session commands to its remote AuthCenter
/// (the "Listener") over the Cris channel.
/// </summary>
[TestFixture]
public class RelayTests
{
    static readonly Type[] _authTypes = [typeof( CurrentLocalParty ),
                                         typeof( CurrentLocalPartyDefaultProvider ),
                                         typeof( AuthCenterFeatureDriver ),
                                         typeof( IAuthenticationSessionOpener ),
                                         typeof( AuthCenterSessionOpener ),
                                         typeof( AuthCenterSessionService ),
                                         typeof( AuthCenterCommandHandlers ),
                                         typeof( IAuthenticationSessionRelay ),
                                         typeof( AuthCenterRelay ),
                                         typeof( AuthCenterRelayHandler ),
                                         typeof( AuthCenterRelayDIContainerDefinition ),
                                         typeof( IAuthenticationSessionEndpoint ),
                                         typeof( CrisAuthenticationService ),
                                         typeof( AuthenticationInfo ),
                                         typeof( AuthCenterApp.FakeActors ),
                                         typeof( RawCrisExecutor ),
                                         typeof( RawCrisReceiver ),
                                         typeof( CrisDirectory ),
                                         typeof( ICrisResultError ),
                                         typeof( IWeakLoginCommand ),
                                         typeof( IBasicLoginCommand ),
                                         typeof( IRefreshSessionCommand ),
                                         typeof( ILogoutSessionCommand ),
                                         typeof( IImpersonateCommand ),
                                         typeof( IClearImpersonationCommand ),
                                         typeof( IGetLoginSchemesQCommand ),
                                         typeof( ISessionResult ),
                                         typeof( IAuthenticationInfoPoco ),
                                         typeof( IActorInfoPoco ),
                                         typeof( IRelaySessionCommand ),
                                         typeof( IRelaySessionResult ),
                                         typeof( IGetAuthCenterEncryptionKeyQCommand ),
                                         typeof( IAuthCenterEncryptionKey ),
                                         typeof( IStartLoginCommand ),
                                         typeof( IRemoteLoginCallbackCommand ),
                                         typeof( AuthCenterOidcHandlers ),
                                         typeof( NormalizedCultureInfoAmbientServiceDefault ),
                                         typeof( TranslationService ),
                                         typeof( NormalizedCultureInfo ),
                                         typeof( CurrentCultureInfo )];

    const int Port = 37145;

    internal sealed class Pair : IAsyncDisposable
    {
        public required RunningApplication Front { get; init; }
        public required RunningApplication Center { get; init; }
        public AuthCenterApp.Browser Browser => Front.Services.GetRequiredService<AuthCenterApp.Browser>();
        public CrisAuthCenter FrontCenter => Front.ApplicationIdentityService.GetRequiredFeature<CrisAuthCenter>();
        public LocalAuthCenter LocalCenter => Center.ApplicationIdentityService.GetRequiredFeature<CrisAuthCenter>().Local.ShouldNotBeNull();

        public async ValueTask DisposeAsync()
        {
            await Front.DisposeAsync();
            await Center.DisposeAsync();
        }

        // A request of the browser to the front: the session command is relayed.
        public async Task<object?> RelayAsync( Func<PocoDirectory, ICommandAuthenticationSession> create )
        {
            await using var scope = Front.CreateAsyncScopeServices();
            var services = scope.ServiceProvider;
            var relay = services.GetRequiredService<IAuthenticationSessionRelay>();
            var t = relay.TryRelay( TestHelper.Monitor, create( services.GetRequiredService<PocoDirectory>() ) ).ShouldNotBeNull( "The AuthCenter is remote." );
            return await t;
        }

        // Relays and, like a front, reads the token (with the safety net of ReadTokenAsync).
        public async Task<object?> SendAsync( Func<PocoDirectory, ICommandAuthenticationSession> create )
        {
            var result = await RelayAsync( create );
            if( result is ISessionResult r && r.Token != null )
            {
                var read = (await FrontCenter.ReadTokenAsync( TestHelper.Monitor, r.Token, DateTime.UtcNow )).ShouldNotBeNull( "The front verifies the token of its remote AuthCenter." );
                Browser.Current = read.Info;
                Browser.Token = r.Token;
            }
            return result;
        }
    }

    static void FrontServices( IServiceCollection services )
    {
        services.AddSingleton<AuthCenterApp.Browser>();
        services.AddScoped<IAuthenticationSessionEndpoint, AuthCenterApp.FakeEndpoint>();
        services.AddScoped( sp => sp.GetRequiredService<AuthCenterApp.Browser>().Current );
        services.AddScoped<IActivityMonitor>( sp => TestHelper.Monitor );
        services.AddScoped( sp => new CurrentLocalParty( sp.GetRequiredService<ApplicationIdentityService>() ) );
    }

    internal static Task<Pair> StartPairAsync() => StartAsync();

    static async Task<Pair> StartAsync( bool frontIsAllowed = true, Action<MutableConfigurationSection>? centerSettings = null )
    {
        // The front has no login provider: its AuthCenter is its remote "$Listener".
        var front = await RunningApplication.CreateAsync( TestHelper.Monitor, true, c =>
        {
            c["AllowFeatures"] = "AuthCenter";
            c["Parties:0:AuthCenter"] = "true";
            // Not RunningApplication.Port: it is the one of CK.AppIdentity.Cris.Tests, that may run concurrently.
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{Port}";
        }, FrontServices, _authTypes );
        // The AuthCenter knows its front: the "$Sender" remote has the AuthCenter feature (unless it is disallowed).
        var center = await RunningApplication.CreateAsync( TestHelper.Monitor, false, c =>
        {
            c["AllowFeatures"] = "AuthCenter";
            c["ListeningAddress:0"] = $"tcp:127.0.0.1:{Port}";
            if( centerSettings != null ) centerSettings( c ); else c["AuthCenter"] = "true";
            if( !frontIsAllowed ) c["Parties:0:DisallowFeatures"] = "AuthCenter";
        }, null, [.. _authTypes, typeof( AuthCenterApp.FakeWeakLoginProvider ), typeof( AuthCenterWeakLoginHandler ), typeof( AuthCenterApp.FakeBasicLoginProvider ), typeof( AuthCenterBasicLoginHandler ), typeof( AuthCenterApp.FakeOidcLoginProvider )] );
        return new Pair { Front = front, Center = center };
    }

    [Test]
    public async Task the_session_commands_are_relayed_to_the_remote_AuthCenter_Async()
    {
        await using var p = await StartAsync();
        p.FrontCenter.IsLocal.ShouldBeFalse();

        // Login: the front has no provider, the AuthCenter logs in, the front's endpoint uses its prepared secrets.
        var login = (ISessionResult)(await p.SendAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Operator" ) )).ShouldNotBeNull();
        login.Success.ShouldBeTrue();
        p.Browser.Current.UnsafeActor.ActorName.ShouldBe( "Operator" );
        var cookies = p.Browser.Cookies.ShouldNotBeNull();
        AuthCenterSession.TryParseSessionKey( cookies.SessionKey, out var actorId, out var sessionId ).ShouldBeTrue();
        var stored = (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldNotBeNull();
        stored.Matches( cookies ).ShouldBeTrue( "The AuthCenter stored the hashes of the secrets prepared by the front." );

        // Refresh: relayed with the presented proof, the secrets rotate.
        var refresh = (ISessionResult)(await p.SendAsync( pocos => pocos.Create<IRefreshSessionCommand>() )).ShouldNotBeNull();
        refresh.Success.ShouldBeTrue();
        p.Browser.Cookies.ShouldNotBeNull().RefreshSecretHash.ShouldNotBe( cookies.RefreshSecretHash );
        (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldNotBeNull().Matches( p.Browser.Cookies! ).ShouldBeTrue();

        // The login schemes are the AuthCenter's ones.
        await using( var scope = p.Front.CreateAsyncScopeServices() )
        {
            var s = scope.ServiceProvider;
            var schemes = (await s.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( s, s.GetRequiredService<PocoDirectory>().Create<IGetLoginSchemesQCommand>() )).Result;
            schemes.ShouldBeAssignableTo<IList<string>>().ShouldBe( ["Basic", "Weak"] );
        }

        // Logout: the session is deleted by the AuthCenter, the front's endpoint is cleared.
        (await p.SendAsync( pocos => pocos.Create<ILogoutSessionCommand>() )).ShouldBeNull();
        p.Browser.Cookies.ShouldBeNull();
        (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldBeNull();
    }

    [Test]
    public async Task an_oidc_login_is_relayed_to_the_remote_AuthCenter_Async()
    {
        const string callback = "https://front.example.com/.auth/oidc/callback";
        using var idp = new FakeIdentityProvider();
        await using var p = await StartAsync( centerSettings: c =>
        {
            c["AuthCenter:Oidc:Test:Authority"] = idp.BaseUrl;
            c["AuthCenter:Oidc:Test:ClientId"] = FakeIdentityProvider.ClientId;
            c["AuthCenter:Oidc:Test:ClientSecret"] = FakeIdentityProvider.ClientSecret;
            c["AuthCenter:Oidc:Test:CallbackUrls:0"] = callback;
        } );
        p.Browser.RemoteLoginCallbackUrl = callback;

        // The front relays the start with its callback and the hash of the correlation it prepared.
        var start = (RedirectedUrl)(await p.RelayAsync( pocos => pocos.Create<IStartLoginCommand>( c => { c.Scheme = "Oidc.Test"; c.ReturnUrl = "/"; } ) )).ShouldNotBeNull();
        p.Browser.RemoteLoginCorrelation.ShouldNotBeNull();
        p.LocalCenter.Oidc.PendingLoginCount.ShouldBe( 1 );

        // The provider redirects the browser to the front, that relays the callback: the code is encrypted for the AuthCenter.
        var (_, code, state) = idp.Authorize( start.Url, "albert-sub" );
        IRemoteLoginCallbackCommand? sent = null;
        var r = (ISessionResult)(await p.SendAsync( pocos => sent = pocos.Create<IRemoteLoginCallbackCommand>( c => { c.State = state; c.Code = code; } ) )).ShouldNotBeNull();
        r.Success.ShouldBeTrue();
        sent.ShouldNotBeNull().Code.ShouldStartWith( "ckenc1:", customMessage: "The relayed command carries the ciphertext of the code." );
        p.Browser.Current.ActualActor.ActorName.ShouldBe( "Albert" );
        var cookies = p.Browser.Cookies.ShouldNotBeNull( "The front's endpoint issued the session." );
        AuthCenterSession.TryParseSessionKey( cookies.SessionKey, out var actorId, out var sessionId ).ShouldBeTrue();
        (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldNotBeNull().Matches( cookies ).ShouldBeTrue();

        // The AuthCenter lists the scheme to the front.
        await using( var scope = p.Front.CreateAsyncScopeServices() )
        {
            var s = scope.ServiceProvider;
            var schemes = (await s.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( s, s.GetRequiredService<PocoDirectory>().Create<IGetLoginSchemesQCommand>() )).Result;
            schemes.ShouldBeAssignableTo<IList<string>>().ShouldNotBeNull().ShouldContain( "Oidc.Test" );
        }
    }

    [Test]
    public async Task the_AuthCenter_executes_locally_Async()
    {
        await using var p = await StartAsync();
        await using var scope = p.Center.CreateAsyncScopeServices();
        // No IAuthenticationSessionEndpoint in the AuthCenter's root container: a local relay only needs the current local party.
        var relay = ActivatorUtilities.CreateInstance<AuthCenterRelay>( scope.ServiceProvider, new CurrentLocalParty( p.Center.ApplicationIdentityService ), new AuthCenterApp.FakeEndpoint( new AuthCenterApp.Browser() ) );
        relay.TryRelay( TestHelper.Monitor, p.Center.PocoDirectory.Create<IRefreshSessionCommand>() ).ShouldBeNull( "The AuthCenter is local: executed here." );
    }

    [Test]
    public async Task the_sensitive_fields_are_encrypted_for_the_AuthCenter_Async()
    {
        await using var p = await StartAsync();
        AuthCenterApp.FakeBasicLoginProvider.LastPassword = null;

        // The password is encrypted in place by the front, the AuthCenter decrypts it before the provider sees it.
        IBasicLoginCommand? sent = null;
        var r = (ISessionResult)(await p.SendAsync( pocos => sent = pocos.Create<IBasicLoginCommand>( c => { c.UserName = "Albert"; c.Password = "secret"; } ) )).ShouldNotBeNull();
        r.Success.ShouldBeTrue();
        p.Browser.Current.ActualActor.ActorName.ShouldBe( "Albert" );
        AuthCenterApp.FakeBasicLoginProvider.LastPassword.ShouldBe( "secret" );
        sent.ShouldNotBeNull().Password.ShouldStartWith( "ckenc1:", customMessage: "The relayed command carries the ciphertext, never the password." );

        var wrong = (ISessionResult)(await p.SendAsync( pocos => pocos.Create<IBasicLoginCommand>( c => { c.UserName = "Albert"; c.Password = "not-the-secret"; } ) )).ShouldNotBeNull();
        wrong.Success.ShouldBeFalse();
        AuthCenterApp.FakeBasicLoginProvider.LastPassword.ShouldBe( "not-the-secret" );

        // A front that sends a clear password (bypassing the relay) is refused.
        AuthCenterApp.FakeBasicLoginProvider.LastPassword = null;
        var channel = p.Front.CrisChannel;
        var clear = p.Front.PocoDirectory.Create<IRelaySessionCommand>( c =>
        {
            c.Command = p.Front.PocoDirectory.Create<IBasicLoginCommand>( b => { b.UserName = "Albert"; b.Password = "secret"; } );
            c.NextRefreshSecretHash = "r";
            c.NextBindingSecretHash = "b";
        } );
        var relayed = await channel.SendCommand( TestHelper.Monitor, clear ).WithResult<IRelaySessionResult>().Result.WaitAsync( TimeSpan.FromSeconds( 30 ) );
        relayed.Result.ShouldBeAssignableTo<ISessionResult>().ShouldNotBeNull().UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.SensitiveNotEncrypted" );
        relayed.IssuedSessionKey.ShouldBeNull();
        AuthCenterApp.FakeBasicLoginProvider.LastPassword.ShouldBeNull( "The provider never saw it." );
    }

    [Test]
    public async Task only_a_front_of_the_AuthCenter_can_relay_Async()
    {
        await using var p = await StartAsync( frontIsAllowed: false );
        var r = (ISessionResult)(await p.SendAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Operator" ) )).ShouldNotBeNull();
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.RelayNotAllowed" );
        p.Browser.Cookies.ShouldBeNull();
    }
}

[TestFixture]
public class RelayKeyRotationTests
{
    [Test]
    public async Task a_front_reads_the_tokens_of_its_AuthCenter_after_a_rotation_it_missed_Async()
    {
        await using var p = await RelayTests.StartPairAsync();
        (await p.SendAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Operator" ) )).ShouldNotBeNull();

        // The AuthCenter rotates its key. These test applications have no heartbeat: nothing is pushed to the front.
        var centerKeys = p.Center.ApplicationIdentityService.GetRequiredFeature<CK.AppIdentity.KeyManagement.ILocalKeys>();
        centerKeys.Rotate( TestHelper.Monitor ).ShouldBeTrue();

        // The refreshed token is signed by the new key: the front is still pinned on the previous one.
        var refresh = (ISessionResult)(await p.RelayAsync( pocos => pocos.Create<IRefreshSessionCommand>() )).ShouldNotBeNull();
        var token = refresh.Token.ShouldNotBeNull();
        var centerOnFront = p.Front.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<CK.AppIdentity.KeyManagement.IRemoteKeys>();
        centerOnFront.TrustedEvent.ShouldNotBeNull().Seq.ShouldBeLessThan( centerKeys.Seq, "The front missed the rotation." );

        // The safety net asks the AuthCenter for its key events and reads the token again.
        var read = (await p.FrontCenter.ReadTokenAsync( TestHelper.Monitor, token, DateTime.UtcNow )).ShouldNotBeNull();
        read.Info.UnsafeActor.ActorName.ShouldBe( "Operator" );
        centerOnFront.TrustedEvent.ShouldNotBeNull().Seq.ShouldBe( centerKeys.Seq, "The pin moved." );
    }
}
