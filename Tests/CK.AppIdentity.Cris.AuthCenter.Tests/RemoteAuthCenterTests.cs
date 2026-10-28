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
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// A remote of an Authentication Center (CK.AppIdentity.Cris.AuthCenter.Remote) and its AuthCenter: the session commands
/// are executed by the remote's endpoint, their operations are dispatched to the AuthCenter; the commands handled by the
/// AuthCenter carry the identity of their user, vouched for by the remote (its CallerPartyId) or proved by the user's
/// token (CK.AppIdentity.Cris.Authentication).
/// </summary>
[TestFixture]
public class RemoteAuthCenterTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 30 );

    // Handled by the AuthCenter: answers the actor, the level and the caller party it executes with.
    public interface IWhoCallsCommand : ICommand<string>, ICommandAuthNormal
    {
    }

    public interface ICriticalWhoCallsCommand : ICommand<string>, ICommandAuthCritical
    {
    }

    public sealed class CenterHandlers : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IWhoCallsCommand c, AuthenticationInfo info ) => $"{info.UnsafeActor.ActorName}/{info.UnsafeActualActor.Level}/{info.CallerPartyId}";

        [CommandHandler]
        public string Handle( ICriticalWhoCallsCommand c, AuthenticationInfo info ) => $"{info.UnsafeActor.ActorName}/{info.UnsafeActualActor.Level}/{info.CallerPartyId}";
    }

    static readonly Type[] _common = [typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( AuthCenterFeatureDriver ),
                                      typeof( IAuthenticationSessionEndpoint ),
                                      typeof( CrisAuthenticationService ),
                                      typeof( AuthenticationInfo ),
                                      typeof( AuthCenterApp.FakeActors ),
                                      typeof( RawCrisExecutor ),
                                      typeof( RawCrisReceiver ),
                                      typeof( CrisDirectory ),
                                      typeof( ICrisResultError ),
                                      typeof( NormalizedCultureInfoAmbientServiceDefault ),
                                      typeof( TranslationService ),
                                      typeof( NormalizedCultureInfo ),
                                      typeof( CurrentCultureInfo ),
                                      typeof( IWeakLoginCommand ),
                                      typeof( IBasicLoginCommand ),
                                      typeof( IRefreshSessionCommand ),
                                      typeof( ILogoutSessionCommand ),
                                      typeof( IImpersonateCommand ),
                                      typeof( IClearImpersonationCommand ),
                                      typeof( ISessionResult ),
                                      typeof( IAuthenticationInfoPoco ),
                                      typeof( IActorInfoPoco ),
                                      typeof( ISessionOperationResult ),
                                      typeof( IOpenSessionOperationCommand ),
                                      typeof( IRefreshSessionOperationCommand ),
                                      typeof( ILogoutSessionOperationCommand ),
                                      typeof( IImpersonateOperationCommand ),
                                      typeof( IClearImpersonationOperationCommand ),
                                      typeof( IGetPartyActorIdsQCommand ),
                                      typeof( IPartyActorIds ),
                                      typeof( IGetAuthCenterEncryptionKeyQCommand ),
                                      typeof( IAuthCenterEncryptionKey ),
                                      typeof( IWhoCallsCommand ),
                                      typeof( ICriticalWhoCallsCommand ),
                                      typeof( IAuthenticationCallContext ),
                                      typeof( AuthenticationReceptionHandler ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService )];

    // The remote: the endpoint side of the session commands, no login provider.
    static readonly Type[] _remoteTypes = [typeof( RemoteAuthCenterFeatureDriver ),
                                           typeof( AuthCenterProofContributor ),
                                           typeof( IAuthenticationSessionOpener ),
                                           typeof( AuthenticationSessionEndpointService ),
                                           typeof( AuthenticationSessionHandlers ),
                                           typeof( WeakLoginHandler ),
                                           typeof( BasicLoginHandler )];

    // The AuthCenter: the operations, the policy for its remotes, the verifier of the user's proofs.
    static readonly Type[] _centerTypes = [typeof( LocalAuthCenterFeatureDriver ),
                                           typeof( AuthCenterOperationHandlers ),
                                           typeof( AuthCenterPartyActorIdsHandler ),
                                           typeof( AuthCenterEncryptionKeyHandler ),
                                           typeof( AuthCenterCallerPartyService ),
                                           typeof( AuthCenterProofVerifier ),
                                           typeof( AuthCenterApp.FakeWeakLoginProvider ),
                                           typeof( AuthCenterApp.FakeBasicLoginProvider ),
                                           typeof( AuthCenterFieldDecryptor ),
                                           typeof( AuthCenterApp.AllowImpersonation ),
                                           typeof( CenterHandlers )];

    const int Port = 37147;

    sealed class Pair : IAsyncDisposable
    {
        public required RunningApplication Remote { get; init; }
        public required RunningApplication Center { get; init; }
        public AuthCenterApp.Browser Browser => Remote.Services.GetRequiredService<AuthCenterApp.Browser>();
        public LocalAuthCenter LocalCenter => Center.ApplicationIdentityService.GetRequiredFeature<LocalAuthCenter>();
        public int RemotePartyActorIdAtTheCenter => Center.ApplicationIdentityService.Remotes.Single().PartyActorId;

        public async ValueTask DisposeAsync()
        {
            await Remote.DisposeAsync();
            await Center.DisposeAsync();
        }

        // A request of the browser to the remote's endpoint.
        public async Task<object?> RequestAsync( Func<PocoDirectory, IAbstractCommand> create )
        {
            await using var scope = Remote.CreateAsyncScopeServices();
            var services = scope.ServiceProvider;
            var command = create( services.GetRequiredService<PocoDirectory>() );
            var result = (await services.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( services, command )).Result;
            // Like a front application, the browser keeps the token it receives (read with the remote's AuthCenter keys).
            if( result is ISessionResult { Token: { } token } )
            {
                var center = Remote.ApplicationIdentityService.GetRequiredFeature<CrisAuthCenter>();
                Browser.Current = (await center.ReadTokenAsync( TestHelper.Monitor, token, DateTime.UtcNow )).ShouldNotBeNull().Info;
                Browser.Token = token;
            }
            return result;
        }

        // A deferred execution on the remote: in the background, without the user's proof.
        public async Task<object?> DeferAsync( Func<PocoDirectory, IAbstractCommand> create )
        {
            using var scope = Remote.CreateScopeServices();
            var hub = scope.ServiceProvider.GetRequiredService<AmbientServiceHub>().CleanClone();
            var command = create( Remote.PocoDirectory );
            var executing = Remote.Services.GetRequiredService<CrisBackgroundExecutorService>().Submit( TestHelper.Monitor, command, hub );
            return (await executing.ExecutedCommand.WaitAsync( _timeout )).Result;
        }
    }

    static void RemoteServices( IServiceCollection services )
    {
        services.AddSingleton<AuthCenterApp.Browser>();
        services.AddScoped<IAuthenticationSessionEndpoint, AuthCenterApp.FakeEndpoint>();
        services.AddScoped( sp => sp.GetRequiredService<AuthCenterApp.Browser>().Current );
        services.AddScoped<IActivityMonitor>( sp => TestHelper.Monitor );
        services.AddScoped( sp => new CurrentLocalParty( sp.GetRequiredService<ApplicationIdentityService>() ) );
    }

    static async Task<Pair> StartAsync( bool remoteIsAllowed = true, bool withRegistrar = true, bool remoteEncrypts = true )
    {
        // The remote's AuthCenter is its remote "$Listener".
        var remote = await RunningApplication.CreateAsync( TestHelper.Monitor, true, c =>
        {
            c["AllowFeatures"] = "AuthCenter";
            c["Parties:0:AuthCenter"] = "true";
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{Port}";
        }, RemoteServices, remoteEncrypts ? [.. _common, .. _remoteTypes, typeof( AuthCenterFieldEncryptor )] : [.. _common, .. _remoteTypes] );
        Type[] centerTypes = withRegistrar ? [.. _common, .. _centerTypes, typeof( PartyActorIdsTests.FakePartyActorFeatureDriver )] : [.. _common, .. _centerTypes];
        var center = await RunningApplication.CreateAsync( TestHelper.Monitor, false, c =>
        {
            c["AllowFeatures"] = "AuthCenter";
            c["ListeningAddress:0"] = $"tcp:127.0.0.1:{Port}";
            c["AuthCenter"] = "true";
            if( !remoteIsAllowed ) c["Parties:0:DisallowFeatures"] = "AuthCenter";
        }, null, centerTypes );
        return new Pair { Remote = remote, Center = center };
    }

    static string Refusal( object? result ) => result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.First().ResName;

    [Test]
    public async Task the_session_commands_are_executed_by_the_remote_endpoint_Async()
    {
        await using var p = await StartAsync();

        // Login: the remote's endpoint executes it, the AuthCenter opens the session (an operation dispatched to it).
        var login = (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Operator" ) )).ShouldBeAssignableTo<ISessionResult>()!;
        login.Success.ShouldBeTrue();
        p.Browser.Current.UnsafeActor.ActorName.ShouldBe( "Operator" );
        var cookies = p.Browser.Cookies.ShouldNotBeNull();
        AuthCenterSession.TryParseSessionKey( cookies.SessionKey, out var actorId, out var sessionId ).ShouldBeTrue();
        (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldNotBeNull().Matches( cookies ).ShouldBeTrue();

        // Refresh: the secrets rotate.
        (await p.RequestAsync( pocos => pocos.Create<IRefreshSessionCommand>() )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        p.Browser.Cookies.ShouldNotBeNull().RefreshSecretHash.ShouldNotBe( cookies.RefreshSecretHash );

        // Logout: the AuthCenter deletes the session, the remote's endpoint clears it.
        await p.RequestAsync( pocos => pocos.Create<ILogoutSessionCommand>() );
        p.Browser.Cookies.ShouldBeNull();
        (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldBeNull();
    }

    [Test]
    public async Task a_command_handled_by_the_AuthCenter_carries_the_identity_vouched_for_or_proved_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var albert = p.Browser.Current.UnsafeActor.ActorId;
        var remoteId = p.RemotePartyActorIdAtTheCenter;
        remoteId.ShouldBeGreaterThan( 0 );

        // A request: the user's proof travels to the AuthCenter, the proved level is kept (Critical just after the login).
        (await p.RequestAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = albert ) )).ShouldBe( $"Albert/Critical/{remoteId}" );
        (await p.RequestAsync( pocos => pocos.Create<ICriticalWhoCallsCommand>( c => c.ActorId = albert ) )).ShouldBe( $"Albert/Critical/{remoteId}" );

        // Deferred (no proof): the remote vouches for Albert, up to Normal (the AuthCenter's policy for its remotes).
        (await p.DeferAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = albert ) )).ShouldBe( $"Albert/Normal/{remoteId}" );
        // A caller party alone never reaches Critical.
        Refusal( await p.DeferAsync( pocos => pocos.Create<ICriticalWhoCallsCommand>( c => c.ActorId = albert ) ) ).ShouldBe( "Authentication.CallerPartyRefused" );
    }

    [Test]
    public async Task the_impersonation_is_a_Critical_operation_that_needs_the_user_proof_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var r = (await p.RequestAsync( pocos => pocos.Create<IImpersonateCommand>( c =>
        {
            c.ActorId = p.Browser.Current.UnsafeActor.ActorId;
            c.TargetActorName = "Paula";
        } ) )).ShouldBeAssignableTo<ISessionResult>()!;
        r.Success.ShouldBeTrue();
        p.Browser.Current.UnsafeActor.ActorName.ShouldBe( "Paula" );
        p.Browser.Current.UnsafeActualActor.ActorName.ShouldBe( "Albert" );
    }

    [Test]
    public async Task a_remote_without_the_AuthCenter_feature_cannot_be_a_caller_party_Async()
    {
        await using var p = await StartAsync( remoteIsAllowed: false );
        // The login is an anonymous operation: any party inside the System may ask for it.
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var albert = p.Browser.Current.UnsafeActor.ActorId;
        // But the AuthCenter's policy refuses this remote as a caller party, and its user's proof is ignored.
        Refusal( await p.DeferAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = albert ) ) ).ShouldBe( "Authentication.CallerPartyRefused" );
        Refusal( await p.RequestAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = albert ) ) ).ShouldBe( "Authentication.CallerPartyRefused" );
    }

    [Test]
    public async Task a_caller_without_PartyActorId_cannot_carry_an_identity_Async()
    {
        await using var p = await StartAsync( withRegistrar: false );
        p.RemotePartyActorIdAtTheCenter.ShouldBe( 0 );
        // An anonymous operation is accepted (the login).
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        // A command that carries an identity is refused.
        Refusal( await p.DeferAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = p.Browser.Current.UnsafeActor.ActorId ) ) ).ShouldBe( "Authentication.CallerPartyRefused" );
    }

    [Test]
    public async Task the_sensitive_fields_are_encrypted_for_the_AuthCenter_Async()
    {
        await using var p = await StartAsync();
        AuthCenterApp.FakeBasicLoginProvider.LastPassword = null;
        IBasicLoginCommand? sent = null;
        var r = await p.RequestAsync( pocos => sent = pocos.Create<IBasicLoginCommand>( c =>
        {
            c.UserName = "Albert";
            c.Password = "secret";
        } ) );
        r.ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        // The AuthCenter decrypted the password (in the payload of the operation that opens the session).
        AuthCenterApp.FakeBasicLoginProvider.LastPassword.ShouldBe( "secret" );
        // A copy has been encrypted: the caller's command is left as is.
        sent.ShouldNotBeNull().Password.ShouldBe( "secret" );
    }

    [Test]
    public async Task a_clear_sensitive_field_is_refused_by_the_AuthCenter_Async()
    {
        await using var p = await StartAsync( remoteEncrypts: false );
        AuthCenterApp.FakeBasicLoginProvider.LastPassword = null;
        var r = await p.RequestAsync( pocos => pocos.Create<IBasicLoginCommand>( c =>
        {
            c.UserName = "Albert";
            c.Password = "secret";
        } ) );
        (r is ISessionResult { Success: true }).ShouldBeFalse();
        AuthCenterApp.FakeBasicLoginProvider.LastPassword.ShouldBeNull();
    }
}
