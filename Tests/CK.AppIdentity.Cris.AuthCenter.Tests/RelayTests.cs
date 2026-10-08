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
                                         typeof( IRelaySessionResult )];

    const int Port = 37145;

    sealed class Pair : IAsyncDisposable
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
        public async Task<object?> SendAsync( Func<PocoDirectory, ICommandAuthenticationSession> create )
        {
            await using var scope = Front.CreateAsyncScopeServices();
            var services = scope.ServiceProvider;
            var relay = services.GetRequiredService<IAuthenticationSessionRelay>();
            var t = relay.TryRelay( TestHelper.Monitor, create( services.GetRequiredService<PocoDirectory>() ) ).ShouldNotBeNull( "The AuthCenter is remote." );
            var result = await t;
            if( result is ISessionResult r && r.Token != null )
            {
                FrontCenter.TryReadToken( TestHelper.Monitor, r.Token, DateTime.UtcNow, out var info, out _ ).ShouldBeTrue( "The front verifies the token of its remote AuthCenter." );
                Browser.Current = info;
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

    static async Task<Pair> StartAsync( bool frontIsAllowed = true )
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
            c["AuthCenter"] = "true";
            if( !frontIsAllowed ) c["Parties:0:DisallowFeatures"] = "AuthCenter";
        }, null, [.. _authTypes, typeof( AuthCenterApp.FakeWeakLoginProvider )] );
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
            schemes.ShouldBeAssignableTo<IList<string>>().ShouldBe( ["Weak"] );
        }

        // Logout: the session is deleted by the AuthCenter, the front's endpoint is cleared.
        (await p.SendAsync( pocos => pocos.Create<ILogoutSessionCommand>() )).ShouldBeNull();
        p.Browser.Cookies.ShouldBeNull();
        (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldBeNull();
    }

    [Test]
    public async Task the_AuthCenter_executes_locally_and_the_sensitive_commands_are_not_relayed_Async()
    {
        await using var p = await StartAsync();
        await using( var scope = p.Center.CreateAsyncScopeServices() )
        {
            // No IAuthenticationSessionEndpoint in the AuthCenter's root container: a local relay only needs the current local party.
            var relay = ActivatorUtilities.CreateInstance<AuthCenterRelay>( scope.ServiceProvider, new CurrentLocalParty( p.Center.ApplicationIdentityService ), new AuthCenterApp.FakeEndpoint( new AuthCenterApp.Browser() ) );
            relay.TryRelay( TestHelper.Monitor, p.Center.PocoDirectory.Create<IRefreshSessionCommand>() ).ShouldBeNull( "The AuthCenter is local: executed here." );
        }
        var r = (ISessionResult)(await p.SendAsync( pocos => pocos.Create<IBasicLoginCommand>( c => { c.UserName = "Albert"; c.Password = "secret"; } ) )).ShouldNotBeNull();
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.SensitiveRelayNotSupported" );
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
