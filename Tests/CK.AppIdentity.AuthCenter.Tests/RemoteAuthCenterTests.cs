using CK.Testing;
using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using CK.IO.Authentication.Basic;
using CK.IO.Authentication.Passkey;
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

namespace CK.AppIdentity.AuthCenter.Tests;

/// <summary>
/// A remote of an Authentication Center (CK.AppIdentity.AuthCenter.Remote) and its AuthCenter: the session commands
/// are executed by the remote's endpoint, their operations are dispatched to the AuthCenter; the commands handled by the
/// AuthCenter carry the identity of their user, vouched for by the remote (its CallerPartyFullName) or proved by the user's
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

    // Sent by the remote to the AuthCenter: its handler dispatches an IEchoCommand back to the remote, from a channel
    // scope (no endpoint there: the user's proof contributor must not fail).
    public interface IRelayCommand : ICommand<string>
    {
    }

    // An anonymous unsafe command (an identity part, no identity): the proof contributor considers it.
    public interface IEchoCommand : ICommand<string>, ICommandAuthUnsafe
    {
    }

    public sealed class RelayHandler : ISingletonAutoService
    {
        [CommandHandler]
        public async Task<string?> HandleAsync( IRelayCommand c, IServiceProvider services, RawCrisExecutor executor, PocoDirectory pocos )
        {
            var r = await executor.RawExecuteAsync( services, pocos.Create<IEchoCommand>( e => e.ActorId = 0 ) );
            return r.Result as string ?? $"Echo failed: {r.Result}";
        }
    }

    public sealed class EchoHandler : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IEchoCommand c, CurrentLocalParty party ) => $"Echo from {party.LocalParty.FullName}";
    }

    public sealed class CenterHandlers : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IWhoCallsCommand c, AuthenticationInfo info ) => $"{info.UnsafeActor.ActorName}/{info.UnsafeActualActor.Level}/{info.CallerPartyFullName}";

        [CommandHandler]
        public string Handle( ICriticalWhoCallsCommand c, AuthenticationInfo info ) => $"{info.UnsafeActor.ActorName}/{info.UnsafeActualActor.Level}/{info.CallerPartyFullName}";
    }

    static readonly Type[] _common = [typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( IAuthenticationSessionEndpoint ),
                                      typeof( CrisAuthenticationService ),
                                      typeof( AuthenticationInfo ),
                                      typeof( FakeActorDatabase ),
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
                                      typeof( IStartLoginCommand ),
                                      typeof( IRemoteLoginCallbackCommand ),
                                      typeof( IGetLoginSchemesQCommand ),
                                      typeof( ILoginSchemeInfo ),
                                      typeof( IStartRemoteLoginOperationCommand ),
                                      typeof( ICompleteRemoteLoginOperationCommand ),
                                      typeof( ISessionResult ),
                                      typeof( IAuthenticationInfoPoco ),
                                      typeof( IActorInfoPoco ),
                                      typeof( ISessionOperationResult ),
                                      typeof( IOpenSessionOperationCommand ),
                                      typeof( IRefreshSessionOperationCommand ),
                                      typeof( ILogoutSessionOperationCommand ),
                                      typeof( IImpersonateOperationCommand ),
                                      typeof( IClearImpersonationOperationCommand ),
                                      typeof( IVerifyCallerProofCommand ),
                                      typeof( IGetRemoteEncryptionKeyQCommand ),
                                      typeof( IPartyEncryptionKeyStatement ),
                                      typeof( IWhoCallsCommand ),
                                      typeof( ICriticalWhoCallsCommand ),
                                      typeof( IRelayCommand ),
                                      typeof( IEchoCommand ),
                                      typeof( IAuthenticationCallEnvelope ),
                                      typeof( IPartyRoutedCommand ),
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
                                           typeof( BasicLoginHandler ),
                                           typeof( EchoHandler )];

    // The AuthCenter: the operations, the policy for its remotes, the verifier of the user's proofs.
    static readonly Type[] _centerTypes = [typeof( LocalAuthCenterFeatureDriver ),
                                           typeof( AuthCenterOperationHandlers ),
                                           typeof( AuthCenterCommandHandlers ),
                                           typeof( AuthCenterCallerPartyService ),
                                           typeof( AuthCenterProofVerifier ),
                                           typeof( VerifyCallerProofHandler ),
                                           typeof( PartyEncryptionKeyDirectoryHandler ),
                                           typeof( FakeWeakLoginProvider ),
                                           typeof( FakeBasicLoginProvider ),
                                           typeof( AuthCenterFieldDecryptor ),
                                           typeof( AuthCenterApp.AllowImpersonation ),
                                           typeof( CenterHandlers ),
                                           typeof( RelayHandler )];

    static readonly Type[] _passkeyCommands = [typeof( IStartPasskeyLoginCommand ),
                                               typeof( IPasskeyLoginCommand ),
                                               typeof( IStartPasskeyRegistrationCommand ),
                                               typeof( IPasskeyRegistrationCommand ),
                                               typeof( IPasskeyRegistrationResult ),
                                               typeof( IStartPasskeyLoginOperationCommand ),
                                               typeof( IFinishPasskeyLoginOperationCommand ),
                                               typeof( IStartPasskeyRegistrationOperationCommand ),
                                               typeof( IFinishPasskeyRegistrationOperationCommand )];

    const int Port = 37147;

    sealed class Pair : IAsyncDisposable
    {
        public required RunningApplication Remote { get; init; }
        public required RunningApplication Center { get; init; }
        public AuthCenterApp.Browser Browser => Remote.Services.GetRequiredService<AuthCenterApp.Browser>();
        public LocalAuthCenter LocalCenter => Center.ApplicationIdentityService.GetRequiredFeature<LocalAuthCenter>();
        public string RemoteFullNameAtTheCenter => Center.ApplicationIdentityService.Remotes.Single().FullName;

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

    static async Task<Pair> StartAsync( bool remoteIsAllowed = true,
                                        bool remoteEncrypts = true,
                                        bool passkeys = false,
                                        Action<MutableConfigurationSection>? oidcSettings = null,
                                        string? centerPublicUrl = null )
    {
        // The remote's AuthCenter is its remote "$Listener".
        Type[] remoteTypes = [.. _common, .. _remoteTypes,
                              .. (remoteEncrypts ? [typeof( AuthCenterFieldEncryptor )] : Type.EmptyTypes),
                              .. (passkeys ? [.. _passkeyCommands, typeof( PasskeyHandlers )] : Type.EmptyTypes)];
        Type[] centerTypes = [.. _common, .. _centerTypes,
                              .. (passkeys
                                    ? [.. _passkeyCommands,
                                       typeof( Passkey.AuthCenterPasskeyFeatureDriver ),
                                       typeof( Passkey.AuthCenterPasskeyConfiguration ),
                                       typeof( Passkey.AuthCenterPasskeyHandlers ),
                                       typeof( InMemoryPasskeyStore ),
                                       typeof( FakePasskeyLoginProvider )]
                                    : Type.EmptyTypes),
                              .. (oidcSettings != null
                                    ? [typeof( Oidc.AuthCenterOidcFeatureDriver ),
                                       typeof( Oidc.AuthCenterOidcConfiguration ),
                                       typeof( FakeOidcLoginProvider )]
                                    : Type.EmptyTypes)];
        // The AuthCenter (the listener) is started first: the remote connects at once.
        var (remote, center) = await RunningApplication.CreatePairAsync( TestHelper.Monitor, c =>
        {
            // The remote announces its public URL: the AuthCenter derives the accepted passkey origins and OIDC callbacks.
            c["Local:PublicUrl"] = "https://front.example.com";
            c["Parties:0:AllowFeatures"] = "AuthCenterRemote";
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{Port}";
        }, remoteTypes, c =>
        {
            c["Defaults:AllowFeatures"] = "AuthCenter,AuthCenterRemote";
            c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{Port}";
            if( !remoteIsAllowed ) c["Parties:0:DisallowFeatures"] = "AuthCenter,AuthCenterRemote";
            if( centerPublicUrl != null ) c["Local:PublicUrl"] = centerPublicUrl;
            // A settings section designates the local party as its own AuthCenter, like "true".
            if( passkeys )
            {
                c["Local:AuthCenter:Passkey:RpId"] = "example.com";
            }
            if( oidcSettings != null ) oidcSettings( c );
        }, centerTypes, RemoteServices );
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
        var remoteId = p.RemoteFullNameAtTheCenter;

        // A request: the user's proof travels to the AuthCenter, the proved level is kept (Critical just after the login).
        (await p.RequestAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = albert ) )).ShouldBe( $"Albert/Critical/{remoteId}" );
        (await p.RequestAsync( pocos => pocos.Create<ICriticalWhoCallsCommand>( c => c.ActorId = albert ) )).ShouldBe( $"Albert/Critical/{remoteId}" );

        // Deferred (no proof): the remote vouches for Albert, up to Normal (the AuthCenter's policy for its remotes).
        (await p.DeferAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = albert ) )).ShouldBe( $"Albert/Normal/{remoteId}" );
        // A caller party alone never reaches Critical.
        Refusal( await p.DeferAsync( pocos => pocos.Create<ICriticalWhoCallsCommand>( c => c.ActorId = albert ) ) ).ShouldBe( "Authentication.CallerPartyRefused" );
    }

    [Test]
    public async Task a_remote_of_the_AuthCenter_verifies_a_relayed_proof_by_asking_it_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = p.Browser.Token.ShouldNotBeNull();
        var binding = p.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;

        // The remote's checker reads the token with the AuthCenter's keys, then asks the AuthCenter for the liveness.
        var checker = p.Remote.ApplicationIdentityService.GetRequiredFeature<IAuthCenterProofChecker>();
        checker.ShouldBeOfType<RemoteAuthCenter>();
        var proved = (await checker.CheckProofAsync( TestHelper.Monitor, token, binding )).ShouldNotBeNull();
        proved.UnsafeActor.ActorName.ShouldBe( "Albert" );
        proved.UnsafeActualActor.Level.ShouldBe( AuthLevel.Critical, "Just after the login: the proved level is kept." );

        (await checker.CheckProofAsync( TestHelper.Monitor, token, AuthCenterApp.Hash( "another-binding" ) )).ShouldBeNull( "The binding secret must be the session's." );
        (await checker.CheckProofAsync( TestHelper.Monitor, "garbage", binding )).ShouldBeNull( "Refused locally, without asking." );

        // The session ends: the AuthCenter refuses the proof.
        await p.RequestAsync( pocos => pocos.Create<ILogoutSessionCommand>() );
        (await checker.CheckProofAsync( TestHelper.Monitor, token, binding )).ShouldBeNull( "The session ended." );
    }

    [Test]
    public async Task a_proof_that_does_not_verify_is_evidence_against_its_sender_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = p.Browser.Token.ShouldNotBeNull();
        var binding = p.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;
        // On the AuthCenter, the proofs sent by its remote.
        var sender = p.Center.ApplicationIdentityService.Remotes.Single();
        var verifier = new AuthCenterProofVerifier();
        using var scope = p.Center.CreateScopeServices();

        (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, sender, null, Proof( p.Center, token, binding ) )).ShouldNotBeNull()
            .UnsafeActor.ActorName.ShouldBe( "Albert" );
        foreach( var (t, b) in new (string, byte[]?)[] { ("garbage", binding), (token, AuthCenterApp.Hash( "another-binding" )), (token, null) } )
        {
            using( TestHelper.Monitor.CollectTexts( out var texts ) )
            {
                (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, sender, null, Proof( p.Center, t, b ) )).ShouldBeNull();
                texts.ShouldContain( x => x.Contains( $"'{sender}' sent a user's proof that doesn't verify" ) );
            }
        }
        // A session that ended is not evidence: a logout may happen while a command travels.
        await p.RequestAsync( pocos => pocos.Create<ILogoutSessionCommand>() );
        using( TestHelper.Monitor.CollectTexts( out var texts ) )
        {
            (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, sender, null, Proof( p.Center, token, binding ) )).ShouldBeNull();
            texts.ShouldNotContain( x => x.Contains( "doesn't verify" ) );
        }
    }

    [Test]
    public async Task only_the_party_that_opened_the_session_presents_its_proof_at_the_Critical_level_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = p.Browser.Token.ShouldNotBeNull();
        var binding = p.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;
        // The session has been opened through the remote: it is the session party.
        var center = p.Center.ApplicationIdentityService.GetRequiredFeature<CrisAuthCenter>();
        var fromRemote = p.Center.ApplicationIdentityService.Remotes.Single();
        (await center.ReadTokenAsync( TestHelper.Monitor, token, DateTime.UtcNow )).ShouldNotBeNull().SessionParty.ShouldBe( fromRemote.FullName.Path );
        var verifier = new AuthCenterProofVerifier();

        // On the AuthCenter, the proof sent by the session party keeps the Critical level.
        using( var scope = p.Center.CreateScopeServices() )
        {
            (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, fromRemote, null, Proof( p.Center, token, binding ) )).ShouldNotBeNull()
                .ActualActor.Level.ShouldBe( AuthLevel.Critical );
        }
        // On the remote, the same proof sent by the AuthCenter (another party than the session party) is capped at Normal.
        var fromCenter = p.Remote.ApplicationIdentityService.Remotes.Single();
        using( var scope = p.Remote.CreateScopeServices() )
        using( TestHelper.Monitor.CollectTexts( out var texts ) )
        {
            var capped = (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, fromCenter, null, Proof( p.Remote, token, binding ) )).ShouldNotBeNull();
            capped.UnsafeActor.ActorName.ShouldBe( "Albert" );
            capped.ActualActor.Level.ShouldBe( AuthLevel.Normal );
            texts.ShouldContain( t => t.Contains( $"'{fromCenter}' sent a user's proof of a session opened by '{fromRemote.FullName}': its level is capped at Normal" ) );
        }
    }

    // A routed command as received by its destination: the bytes of the command, the path from the origin.
    static IPartyRoutedCommand Routed( RunningApplication destination, string origin, byte[] sealedCommand )
    {
        return destination.PocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.SealedCommand = sealedCommand;
            r.Via.AddRange( [origin, "Test/$Hop"] );
        } );
    }

    [Test]
    public async Task the_AuthCenter_is_the_key_directory_of_its_remotes_Async()
    {
        await using var p = await StartAsync();
        var remote = p.Remote.ApplicationIdentityService;
        var center = p.Center.ApplicationIdentityService;
        string remoteName = remote.FullName.Path;
        string centerName = center.FullName.Path;
        // The descriptions (with the encryption keys) are exchanged on connection.
        var remoteAtCenter = center.Remotes.Single();
        var centerAtRemote = remote.Remotes.Single();
        for( int i = 0; i < 100 && (remoteAtCenter.Description.EncryptionKey == null || centerAtRemote.Description.EncryptionKey == null); ++i )
        {
            await Task.Delay( 100 );
        }
        var remoteKey = remote.Description.EncryptionKey.ShouldNotBeNull().PublicKey.ToArray();
        var centerKey = center.Description.EncryptionKey.ShouldNotBeNull().PublicKey.ToArray();

        // On the AuthCenter: its own key and the ones of its remotes, from their descriptions (verified).
        var local = center.GetRequiredFeature<LocalAuthCenter>();
        (await local.GetPartyEncryptionKeyAsync( TestHelper.Monitor, remoteName )).ShouldNotBeNull().PublicKey.ShouldBe( remoteKey );
        (await local.GetPartyEncryptionKeyAsync( TestHelper.Monitor, centerName )).ShouldNotBeNull().PublicKey.ShouldBe( centerKey );
        (await local.GetPartyEncryptionKeyAsync( TestHelper.Monitor, "Test/$Unknown" )).ShouldBeNull();

        // On its remote: the AuthCenter's key from its description, the key of another party from the statement of the
        // AuthCenter (here, the remote itself: the AuthCenter vouches for its remotes).
        var directory = remote.GetRequiredFeature<IPartyEncryptionKeyDirectory>();
        (await directory.GetPartyEncryptionKeyAsync( TestHelper.Monitor, centerName )).ShouldNotBeNull().PublicKey.ShouldBe( centerKey );
        var stated = (await directory.GetPartyEncryptionKeyAsync( TestHelper.Monitor, remoteName )).ShouldNotBeNull();
        stated.PublicKey.ShouldBe( remoteKey );
        stated.Expires.ShouldBeGreaterThan( DateTime.UtcNow );
        (await directory.GetPartyEncryptionKeyAsync( TestHelper.Monitor, "Test/$Unknown" )).ShouldBeNull();
    }

    [Test]
    public async Task a_command_dispatched_from_a_channel_scope_carries_no_proof_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        // The relay is received by the AuthCenter on its channel: its handler dispatches the echo to the remote from the
        // channel scope, where no endpoint presents a token.
        (await p.RequestAsync( pocos => pocos.Create<IRelayCommand>() )).ShouldBe( $"Echo from {p.Remote.ApplicationIdentityService.FullName}" );
    }

    [Test]
    public async Task the_proof_of_a_routed_command_needs_the_seal_of_the_session_party_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = p.Browser.Token.ShouldNotBeNull();
        var binding = p.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;
        // The remote opened the session: it is the session party, the origin of the routes.
        var sessionParty = p.Remote.ApplicationIdentityService;
        var sessionKeys = sessionParty.GetRequiredFeature<ILocalKeys>();
        string origin = sessionParty.FullName.Path;
        string centerName = p.Center.ApplicationIdentityService.FullName.Path;
        byte[] command = [1, 2, 3, 4];
        var verifier = new AuthCenterProofVerifier();
        // The sender of a routed command is its last hop: here, the remote as known by the AuthCenter.
        var lastHop = p.Center.ApplicationIdentityService.Remotes.Single();
        using var scope = p.Center.CreateScopeServices();
        var seal = new AuthCenterRoutedCommandSeal();
        // The session party encrypts for the AuthCenter with the key of its description.
        for( int i = 0; i < 100 && sessionParty.Remotes.Single().Description.EncryptionKey == null; ++i ) await Task.Delay( 100 );

        IAuthenticationCallEnvelope Sealed( string destination, byte[] sealedBytes )
        {
            var e = Proof( p.Center, token, binding );
            (e.RoutedSeal, e.RoutedSignature) = RoutedCommandSeal.Create( sessionKeys, destination, token, sealedBytes, DateTime.UtcNow );
            return e;
        }
        // The seal of the origin (the session party): its hook signs the routed command that carries the proof.
        async Task<IAuthenticationCallEnvelope> SealedByTheHookAsync( string destination, IPartyRoutedCommand routedAtOrigin )
        {
            var e = Proof( p.Center, token, binding );
            (await seal.SealAsync( TestHelper.Monitor, null!, sessionParty, destination, null!, routedAtOrigin, e )).ShouldBeTrue();
            e.RoutedSeal.ShouldNotBeNull();
            return e;
        }
        async Task RefusedAsync( IPartyRoutedCommand route, IAuthenticationCallEnvelope proof, string because )
        {
            using( TestHelper.Monitor.CollectTexts( out var texts ) )
            {
                (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, route, proof )).ShouldBeNull( because );
                texts.ShouldContain( t => t.Contains( because ) );
            }
        }

        // Sealed by the session party (its hook) for the AuthCenter: encrypted, a hop sees neither the command nor the proof.
        var route = Routed( p.Center, origin, command );
        var proof = await SealedByTheHookAsync( centerName, route );
        route.SealedCommand.ShouldNotBe( command );
        proof.Token.ShouldBeNull();
        proof.BindingSecretHash.ShouldBeNull();
        // An altered ciphertext can't be decrypted by the AuthCenter (the destination).
        var altered = Routed( p.Center, origin, route.SealedCommand!.ToArray() );
        altered.SealedCommand![^1] ^= 1;
        (await seal.UnsealAsync( TestHelper.Monitor, lastHop, altered, proof )).ShouldBeNull();
        // The AuthCenter decrypts it: the command and the proof are back, the Critical level is kept.
        (await seal.UnsealAsync( TestHelper.Monitor, lastHop, route, proof )).ShouldBe( command );
        proof.Token.ShouldBe( token );
        proof.BindingSecretHash.ShouldBe( binding );
        (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, route, proof )).ShouldNotBeNull()
            .ActualActor.Level.ShouldBe( AuthLevel.Critical );
        // No verified encryption key for the destination: signed only, in clear, the proof in the envelope.
        var signedOnly = Routed( p.Center, origin, command );
        var signedOnlyProof = await SealedByTheHookAsync( "Test/$Unknown", signedOnly );
        signedOnly.SealedCommand.ShouldBe( command );
        signedOnlyProof.Token.ShouldBe( token );
        (await seal.UnsealAsync( TestHelper.Monitor, lastHop, signedOnly, signedOnlyProof )).ShouldBe( command );
        // A seal is used once.
        await RefusedAsync( route, proof, "it has already been used" );
        // No seal.
        await RefusedAsync( route, Proof( p.Center, token, binding ), "has no seal" );
        // Another command than the sealed one.
        await RefusedAsync( Routed( p.Center, origin, [9, 9, 9] ), Sealed( centerName, command ), "is invalid: the proof is refused" );
        // Sealed for another destination.
        await RefusedAsync( route, Sealed( "Test/$Other", command ), "it has been made for 'Test/$Other'" );
        // Another origin than the session party.
        await RefusedAsync( Routed( p.Center, "Test/$Evil", command ), Sealed( centerName, command ), "is routed from 'Test/$Evil > Test/$Hop'" );
    }

    [Test]
    public async Task a_remote_of_the_AuthCenter_has_the_seal_of_a_routed_proof_verified_by_the_AuthCenter_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = p.Browser.Token.ShouldNotBeNull();
        var binding = p.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;
        // The destination is the remote: it can't verify the seal itself, the AuthCenter does (the remote asks it).
        // The session party is the remote too (it opened the session): enough to exercise the verification by the AuthCenter.
        var remote = p.Remote.ApplicationIdentityService;
        var keys = remote.GetRequiredFeature<ILocalKeys>();
        string remoteName = remote.FullName.Path;
        byte[] command = [5, 6, 7];
        var verifier = new AuthCenterProofVerifier();
        var lastHop = remote.Remotes.Single();
        using var scope = p.Remote.CreateScopeServices();

        var proof = Proof( p.Remote, token, binding );
        (proof.RoutedSeal, proof.RoutedSignature) = RoutedCommandSeal.Create( keys, remoteName, token, command, DateTime.UtcNow );
        (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, Routed( p.Remote, remoteName, command ), proof )).ShouldNotBeNull()
            .ActualActor.Level.ShouldBe( AuthLevel.Critical );

        // Sealed for another destination: the AuthCenter checks that the asking party is the destination.
        var other = Proof( p.Remote, token, binding );
        (other.RoutedSeal, other.RoutedSignature) = RoutedCommandSeal.Create( keys, "Test/$Other", token, command, DateTime.UtcNow );
        (await verifier.VerifyAsync( TestHelper.Monitor, scope.ServiceProvider, lastHop, Routed( p.Remote, remoteName, command ), other )).ShouldBeNull();
    }

    [Test]
    public async Task a_routed_proof_is_relayed_only_when_it_verifies_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var token = p.Browser.Token.ShouldNotBeNull();
        var binding = p.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;
        // The remote forwards: it reads the proof with the AuthCenter's keys (no round trip).
        var sender = p.Remote.ApplicationIdentityService.Remotes.Single();
        var filter = new AuthCenterProofForwardFilter();

        var valid = Proof( p.Remote, token, binding );
        await filter.FilterAsync( TestHelper.Monitor, sender, sender, null!, valid );
        valid.Token.ShouldBe( token );
        valid.BindingSecretHash.ShouldBe( binding );

        foreach( var (t, b) in new (string, byte[]?)[] { ("garbage", binding), (token, AuthCenterApp.Hash( "another-binding" )), (token, null) } )
        {
            var bad = Proof( p.Remote, t, b );
            using( TestHelper.Monitor.CollectTexts( out var texts ) )
            {
                await filter.FilterAsync( TestHelper.Monitor, sender, sender, null!, bad );
                texts.ShouldContain( x => x.Contains( $"'{sender}' sent a user's proof that doesn't verify: it is not relayed" ) );
            }
            bad.Token.ShouldBeNull();
            bad.BindingSecretHash.ShouldBeNull();
        }
    }

    static IAuthenticationCallEnvelope Proof( RunningApplication app, string token, byte[]? binding )
    {
        var e = (IAuthenticationCallEnvelope)app.PocoDirectory.Create<ICrisCallEnvelope>();
        e.Token = token;
        e.BindingSecretHash = binding;
        return e;
    }

    [Test]
    public async Task when_the_AuthCenter_cannot_be_reached_a_relayed_proof_is_not_verified_Async()
    {
        var p = await StartAsync();
        try
        {
            (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
            var token = p.Browser.Token.ShouldNotBeNull();
            var binding = p.Browser.Cookies.ShouldNotBeNull().BindingSecretHash;
            var checker = p.Remote.ApplicationIdentityService.GetRequiredFeature<IAuthCenterProofChecker>();
            await p.Center.DisposeAsync();
            (await checker.CheckProofAsync( TestHelper.Monitor, token, binding )).ShouldBeNull( "Fail closed: the liveness can't be known." );
        }
        finally
        {
            await p.Remote.DisposeAsync();
        }
    }

    [Test]
    public async Task the_impersonation_is_a_Critical_operation_that_needs_the_user_proof_Async()
    {
        await using var p = await StartAsync();
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var r = (await p.RequestAsync( pocos => pocos.Create<IImpersonateCommand>( c =>
        {
            c.ActorId = p.Browser.Current.UnsafeActor.ActorId;
            c.TargetActorName = "Robert";
        } ) )).ShouldBeAssignableTo<ISessionResult>()!;
        r.Success.ShouldBeTrue();
        p.Browser.Current.UnsafeActor.ActorName.ShouldBe( "Robert" );
        p.Browser.Current.UnsafeActualActor.ActorName.ShouldBe( "Albert" );
    }

    [Test]
    public async Task a_remote_refused_as_caller_party_still_presents_the_proof_of_its_users_Async()
    {
        await using var p = await StartAsync( remoteIsAllowed: false );
        // The login is an anonymous operation: any party inside the System may ask for it.
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var albert = p.Browser.Current.UnsafeActor.ActorId;
        // The AuthCenter's policy refuses this remote as a caller party: without a proof, nothing is vouched for.
        Refusal( await p.DeferAsync( pocos => pocos.Create<IWhoCallsCommand>( c => c.ActorId = albert ) ) ).ShouldBe( "Authentication.CallerPartyRefused" );
        // But its users' proof is verified by the AuthCenter: the remote opened their session (it is the session party), the
        // proved level is kept.
        (await p.RequestAsync( pocos => pocos.Create<ICriticalWhoCallsCommand>( c => c.ActorId = albert ) )).ShouldBe( $"Albert/Critical/{p.RemoteFullNameAtTheCenter}" );
    }

    [Test]
    public async Task the_sensitive_fields_are_encrypted_for_the_AuthCenter_Async()
    {
        await using var p = await StartAsync();
        IBasicLoginCommand? sent = null;
        var r = await p.RequestAsync( pocos => sent = pocos.Create<IBasicLoginCommand>( c =>
        {
            c.UserName = "Albert";
            c.Password = FakeActorDatabase.BasicPassword;
        } ) );
        r.ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        // The AuthCenter decrypted the password (in the payload of the operation that opens the session).
        p.Center.Services.GetRequiredService<FakeBasicLoginProvider>().LastPassword.ShouldBe( FakeActorDatabase.BasicPassword );
        // A copy has been encrypted: the caller's command is left as is.
        sent.ShouldNotBeNull().Password.ShouldBe( FakeActorDatabase.BasicPassword );
    }

    [Test]
    public async Task a_clear_sensitive_field_is_refused_by_the_AuthCenter_Async()
    {
        await using var p = await StartAsync( remoteEncrypts: false );
        var r = await p.RequestAsync( pocos => pocos.Create<IBasicLoginCommand>( c =>
        {
            c.UserName = "Albert";
            c.Password = FakeActorDatabase.BasicPassword;
        } ) );
        (r is ISessionResult { Success: true }).ShouldBeFalse();
        p.Center.Services.GetRequiredService<FakeBasicLoginProvider>().LastPassword.ShouldBeNull();
    }

    [Test]
    public async Task a_passkey_registration_and_login_go_through_the_remote_with_its_origin_Async()
    {
        await using var p = await StartAsync( passkeys: true );
        using var authenticator = new SoftAuthenticator();

        // Albert logs in (Critical) and registers a passkey: the registration operations are Critical, they reach the
        // AuthCenter with the user's proof and the remote's origin.
        (await p.RequestAsync( pocos => pocos.Create<IWeakLoginCommand>( c => c.WeakActorName = "Albert" ) )).ShouldBeAssignableTo<ISessionResult>()!.Success.ShouldBeTrue();
        var albert = p.Browser.Current.UnsafeActor.ActorId;
        var options = (await p.RequestAsync( pocos => pocos.Create<IStartPasskeyRegistrationCommand>( c => c.ActorId = albert ) )).ShouldBeOfType<string>();
        var registered = (await p.RequestAsync( pocos => pocos.Create<IPasskeyRegistrationCommand>( c =>
        {
            c.ActorId = albert;
            c.Response = authenticator.Create( options );
        } ) )).ShouldBeAssignableTo<IPasskeyRegistrationResult>()!;
        registered.Success.ShouldBeTrue();

        // A passkey login through the remote.
        var loginOptions = (await p.RequestAsync( pocos => pocos.Create<IStartPasskeyLoginCommand>() )).ShouldBeOfType<string>();
        var r = (await p.RequestAsync( pocos => pocos.Create<IPasskeyLoginCommand>( c => c.Response = authenticator.Get( loginOptions ) ) )).ShouldBeAssignableTo<ISessionResult>()!;
        r.Success.ShouldBeTrue();
        p.Browser.Current.UnsafeActor.ActorName.ShouldBe( "Albert" );

        // A remote's endpoint whose origin is not configured is refused by the AuthCenter.
        p.Browser.WebOrigin = "https://other.example.com";
        (await p.RequestAsync( pocos => pocos.Create<IStartPasskeyLoginCommand>() )).ShouldBeAssignableTo<ICrisResultError>()!
            .Errors.Select( e => e.Text ).ShouldContain( "The origin 'https://other.example.com' is not allowed for passkeys." );
    }

    [Test]
    public async Task an_oidc_login_goes_through_the_remote_Async()
    {
        const string callback = "https://front.example.com/.auth/oidc/callback";
        using var idp = new FakeIdentityProvider();
        await using var p = await StartAsync( oidcSettings: c =>
        {
            c["Local:AuthCenter:Oidc:Test:Authority"] = idp.BaseUrl;
            c["Local:AuthCenter:Oidc:Test:ClientId"] = FakeIdentityProvider.ClientId;
            c["Local:AuthCenter:Oidc:Test:ClientSecret"] = FakeIdentityProvider.ClientSecret;
        } );
        p.Browser.RemoteLoginCallbackUrl = callback;

        // The remote's endpoint starts the login with its callback and the hash of the correlation it prepared.
        var start = (await p.RequestAsync( pocos => pocos.Create<IStartLoginCommand>( c => { c.Scheme = "Oidc.Test"; c.ReturnUrl = "/"; } ) )).ShouldBeOfType<RedirectedUrl>();
        p.Browser.RemoteLoginCorrelation.ShouldNotBeNull();
        p.LocalCenter.PendingRemoteLogins.Count.ShouldBe( 1 );

        // The provider redirects the browser to the remote's endpoint, that completes the login: the code travels encrypted
        // for the AuthCenter (in a copy: the remote's command keeps it).
        var (_, code, state) = idp.Authorize( start.Url, "albert-sub" );
        IRemoteLoginCallbackCommand? sent = null;
        var r = (await p.RequestAsync( pocos => sent = pocos.Create<IRemoteLoginCallbackCommand>( c => { c.State = state; c.Code = code; } ) )).ShouldBeAssignableTo<ISessionResult>()!;
        r.Success.ShouldBeTrue();
        sent.ShouldNotBeNull().Code.ShouldBe( code );
        p.Browser.Current.ActualActor.ActorName.ShouldBe( "Albert" );
        var cookies = p.Browser.Cookies.ShouldNotBeNull( "The remote's endpoint issued the session." );
        AuthCenterSession.TryParseSessionKey( cookies.SessionKey, out var actorId, out var sessionId ).ShouldBeTrue();
        (await p.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId )).ShouldNotBeNull().Matches( cookies ).ShouldBeTrue();

        // The login schemes are the AuthCenter's ones (dispatched: the remote has no handler).
        (await p.RequestAsync( pocos => pocos.Create<IGetLoginSchemesQCommand>() )).ShouldBeAssignableTo<IList<ILoginSchemeInfo>>()!.Select( s => s.Name ).ShouldContain( "Oidc.Test" );
    }
    [Test]
    public async Task a_remote_cannot_relay_a_login_on_the_origin_of_another_party_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var p = await StartAsync( passkeys: true,
                                              oidcSettings: c =>
                                              {
                                                  c["Local:AuthCenter:Oidc:Test:Authority"] = idp.BaseUrl;
                                                  c["Local:AuthCenter:Oidc:Test:ClientId"] = FakeIdentityProvider.ClientId;
                                                  c["Local:AuthCenter:Oidc:Test:ClientSecret"] = FakeIdentityProvider.ClientSecret;
                                              },
                                              centerPublicUrl: "https://center.example.com" );
        // The AuthCenter is a party (it announces its public URL), but the remote relays: only the remote's origin is accepted.
        p.Browser.RemoteLoginCallbackUrl = "https://center.example.com/.auth/oidc/callback";
        var start = await p.RequestAsync( pocos => pocos.Create<IStartLoginCommand>( c => c.Scheme = "Oidc.Test" ) );
        start.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Select( e => e.Text )
             .ShouldContain( "The callback 'https://center.example.com/.auth/oidc/callback' is not allowed for the scheme 'Oidc.Test'." );
        p.LocalCenter.PendingRemoteLogins.Count.ShouldBe( 0 );

        p.Browser.WebOrigin = "https://center.example.com";
        (await p.RequestAsync( pocos => pocos.Create<IStartPasskeyLoginCommand>() )).ShouldBeAssignableTo<ICrisResultError>()!
            .Errors.Select( e => e.Text ).ShouldContain( "The origin 'https://center.example.com' is not allowed for passkeys." );
    }

    [Test]
    public async Task a_login_started_through_a_remote_is_completed_through_it_only_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var p = await StartAsync( oidcSettings: c =>
                                              {
                                                  c["Local:AuthCenter:Oidc:Test:Authority"] = idp.BaseUrl;
                                                  c["Local:AuthCenter:Oidc:Test:ClientId"] = FakeIdentityProvider.ClientId;
                                                  c["Local:AuthCenter:Oidc:Test:ClientSecret"] = FakeIdentityProvider.ClientSecret;
                                              },
                                              centerPublicUrl: "https://center.example.com" );
        var start = (await p.RequestAsync( pocos => pocos.Create<IStartLoginCommand>( c => c.Scheme = "Oidc.Test" ) )).ShouldBeOfType<RedirectedUrl>();
        var (_, code, state) = idp.Authorize( start.Url, "albert-sub" );

        // The same completion (state, code and correlation) executed by the AuthCenter itself (another party) is refused.
        using var scope = p.Center.CreateScopeServices();
        var hub = scope.ServiceProvider.GetRequiredService<AmbientServiceHub>().CleanClone();
        var op = p.Center.PocoDirectory.Create<ICompleteRemoteLoginOperationCommand>( c =>
        {
            c.Callback = p.Center.PocoDirectory.Create<IRemoteLoginCallbackCommand>( cb => { cb.State = state; cb.Code = code; } );
            c.PresentedCorrelationHash = p.Browser.RemoteLoginCorrelation;
        } );
        var executing = p.Center.Services.GetRequiredService<CrisBackgroundExecutorService>().Submit( TestHelper.Monitor, op, hub );
        var r = (await executing.ExecutedCommand.WaitAsync( _timeout )).Result
                    .ShouldBeAssignableTo<ISessionOperationResult>()!.Result.ShouldNotBeNull();
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.RemoteLoginCorrelation" );
        // The pending login is consumed (one use): the remote can't complete it anymore.
        p.LocalCenter.PendingRemoteLogins.Count.ShouldBe( 0 );
    }
}
