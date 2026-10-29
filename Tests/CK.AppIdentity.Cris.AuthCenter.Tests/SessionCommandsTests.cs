using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// The session commands of a local AuthCenter (executed by the endpoint, their operations by the <see cref="AuthCenterOperationHandlers"/>).
/// </summary>
[TestFixture]
public class SessionCommandsTests
{
    static Task<ISessionResult> RefreshAsync( AuthCenterApp app ) => app.ExecuteSessionAsync( p => p.Create<IRefreshSessionCommand>() );

    static async Task<AuthCenterSession?> ReadSessionAsync( AuthCenterApp app )
    {
        var key = app.Caller.Issued[^1].SessionKey;
        AuthCenterSession.TryParseSessionKey( key, out var actorId, out var sessionId ).ShouldBeTrue();
        return await app.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId );
    }

    [Test]
    public async Task refresh_rotates_the_secrets_and_a_replayed_secret_revokes_the_session_Async()
    {
        // Without the grace window (the previous secrets are then a reuse at once): see RefreshGraceTests for the window.
        await using var app = await AuthCenterApp.StartAsync( c =>
        {
            AuthCenterApp.LocalAuthCenter( c );
            c["Local:AuthCenter:RefreshGraceWindow"] = "0";
        } );
        (await app.LoginAsync( "Albert" )).Info.UnsafeActor.Level.ShouldBe( AuthLevel.Critical );
        var firstCookies = app.Caller.Cookies.ShouldNotBeNull();
        var firstEnd = (await ReadSessionAsync( app )).ShouldNotBeNull().Expires;
        await Task.Delay( 20 );

        var r = await RefreshAsync( app );
        r.Success.ShouldBeTrue();
        r.Token.ShouldNotBeNull();
        r.Info.UnsafeActor.Level.ShouldBe( AuthLevel.Normal, "The Critical level requires a login." );
        app.Caller.Current.Actor.ActorName.ShouldBe( "Albert" );
        var cookies = app.Caller.Cookies.ShouldNotBeNull();
        cookies.SessionKey.ShouldBe( firstCookies.SessionKey );
        cookies.RefreshSecretHash.ShouldNotBe( firstCookies.RefreshSecretHash );
        var refreshed = (await ReadSessionAsync( app )).ShouldNotBeNull();
        refreshed.Matches( cookies ).ShouldBeTrue();
        refreshed.Expires.ShouldBeGreaterThan( firstEnd, "The session slides." );
        app.Caller.Issued[^1].RefreshExpires.ShouldBe( refreshed.Expires );

        // The first secrets are presented again: they have been stolen (or copied). The session is revoked.
        app.Caller.Cookies = firstCookies;
        var replay = await RefreshAsync( app );
        replay.Success.ShouldBeFalse();
        replay.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.InvalidSession" );
        app.Caller.Cookies.ShouldBeNull( "The endpoint secrets are cleared." );
        (await ReadSessionAsync( app )).ShouldBeNull();

        // Even the legitimate caller lost the session.
        app.Caller.Cookies = cookies;
        (await RefreshAsync( app )).Success.ShouldBeFalse();
    }

    [Test]
    public async Task refresh_reads_the_actors_again_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        await app.LoginAsync( "Operator" );
        AuthCenterApp.FakeActors.Disabled.Add( 42 );
        try
        {
            var r = await RefreshAsync( app );
            r.Success.ShouldBeFalse();
            r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.InvalidActor" );
            (await ReadSessionAsync( app )).ShouldBeNull();
        }
        finally
        {
            AuthCenterApp.FakeActors.Disabled.Remove( 42 );
        }
        (await RefreshAsync( app )).UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.NoSession" );
    }

    [Test]
    public async Task logout_ends_the_session_but_the_session_key_alone_proves_nothing_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        await app.LoginAsync( "Operator" );
        var cookies = app.Caller.Cookies.ShouldNotBeNull();

        // The session key is not a secret: with other secrets, a logout deletes nothing.
        app.Caller.Cookies = cookies with { RefreshSecretHash = "forged", BindingSecretHash = "forged" };
        await app.ExecuteAsync( p => p.Create<ILogoutSessionCommand>() );
        app.Caller.Cookies.ShouldBeNull();
        (await ReadSessionAsync( app )).ShouldNotBeNull();

        app.Caller.Cookies = cookies;
        await app.ExecuteAsync( p => p.Create<ILogoutSessionCommand>() );
        app.Caller.Cookies.ShouldBeNull();
        (await ReadSessionAsync( app )).ShouldBeNull();
    }

    [Test]
    public async Task impersonation_is_refused_by_default_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        await app.LoginAsync( "Albert" );
        var r = await app.ExecuteSessionAsync( p => p.Create<IImpersonateCommand>( c => c.TargetActorName = "Paula" ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.ImpersonationNotAllowed" );
    }

    [Test]
    public async Task impersonation_and_its_end_Async()
    {
        await using var app = await AuthCenterApp.StartAsync( allowImpersonation: true );

        // A weak actor (Unsafe) cannot impersonate.
        await app.LoginAsync( "Operator" );
        (await app.ExecuteSessionAsync( p => p.Create<IImpersonateCommand>( c => c.TargetActorName = "Paula" ) ))
            .UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.CriticalLevelRequired" );

        await app.LoginAsync( "Albert" );
        (await app.ExecuteSessionAsync( p => p.Create<IImpersonateCommand>( c => { c.TargetActorId = 12; c.TargetActorName = "Paula"; } ) ))
            .UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.InvalidImpersonation" );
        (await app.ExecuteSessionAsync( p => p.Create<IImpersonateCommand>( c => c.TargetActorId = 3712 ) ))
            .UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.InvalidImpersonation" );

        var r = await app.ExecuteSessionAsync( p => p.Create<IImpersonateCommand>( c => c.TargetActorName = "Paula" ) );
        r.Success.ShouldBeTrue();
        app.Caller.Current.IsImpersonated.ShouldBeTrue();
        app.Caller.Current.ActualActor.ActorName.ShouldBe( "Albert" );
        app.Caller.Current.Actor.ActorName.ShouldBe( "Paula" );
        (await ReadSessionAsync( app )).ShouldNotBeNull().ActorId.ShouldBe( 12 );

        // The impersonation survives a refresh.
        (await RefreshAsync( app )).Success.ShouldBeTrue();
        app.Caller.Current.Actor.ActorName.ShouldBe( "Paula" );
        app.Caller.Current.ActualActor.ActorName.ShouldBe( "Albert" );

        // And it ends.
        (await app.ExecuteSessionAsync( p => p.Create<IClearImpersonationCommand>() )).Success.ShouldBeTrue();
        app.Caller.Current.IsImpersonated.ShouldBeFalse();
        app.Caller.Current.Actor.ActorName.ShouldBe( "Albert" );
        (await ReadSessionAsync( app )).ShouldNotBeNull().ActorId.ShouldBe( 3712 );
    }

    [Test]
    public async Task the_login_schemes_are_the_provider_names_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var schemes = (IList<ILoginSchemeInfo>)(await app.ExecuteAsync( p => p.Create<IGetLoginSchemesQCommand>() )).ShouldNotBeNull();
        schemes.Select( s => (s.Name, s.CriticalLifetime) ).ShouldBe( [("Weak", TimeSpan.Zero)] );
    }

    [Test]
    public async Task without_a_scheme_family_package_its_schemes_do_not_exist_Async()
    {
        // The configuration has no "AuthCenter:Oidc" section (it would be an error without the package).
        await using var app = await AuthCenterApp.StartAsync( withOidc: false );
        app.LocalCenter.SchemeFamilies.ShouldBeEmpty();
        var start = await app.ExecuteAsync( p => p.Create<IStartLoginCommand>( c => c.Scheme = "Oidc.Test" ) );
        start.ShouldBeAssignableTo<ICrisResultError>().ShouldNotBeNull().Errors.Select( e => e.Text ).ShouldContain( "Unknown login scheme 'Oidc.Test'." );
    }
}

[TestFixture]
public class SessionPurgeTests
{
    [Test]
    public async Task the_purge_deletes_the_expired_sessions_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var local = app.LocalCenter;
        var store = local.Sessions;
        var utcNow = System.DateTime.UtcNow;
        var lifetime = local.Options.SessionLifetime;
        var root = app.Identity.LocalFileStore.FolderPath.Combine( "AuthCenter/Sessions" );
        // The test store persists between runs: starts clean.
        if( System.IO.Directory.Exists( root ) ) System.IO.Directory.Delete( root, recursive: true );

        async Task<AuthCenterSession> SaveAsync( int actorId, System.DateTime expires, System.DateTime lastWrite )
        {
            var s = new AuthCenterSession( AuthCenterSession.NewSessionId(), actorId, actorId, utcNow, expires, false, "D", "r", "b" );
            await store.SaveAsync( s );
            System.IO.File.SetLastWriteTimeUtc( root.AppendPart( actorId.ToString() ).AppendPart( s.SessionId ), lastWrite );
            return s;
        }
        var expired = await SaveAsync( 1001, utcNow.AddHours( -1 ), utcNow - lifetime - System.TimeSpan.FromHours( 1 ) );
        var alive = await SaveAsync( 1002, utcNow.AddHours( 1 ), utcNow - lifetime - System.TimeSpan.FromHours( 1 ) );
        var recent = await SaveAsync( 1003, utcNow.AddHours( -1 ), utcNow );
        // A candidate that cannot be read cannot be used: it is deleted.
        var corrupted = AuthCenterSession.NewSessionId();
        System.IO.File.WriteAllText( root.AppendPart( "1002" ).AppendPart( corrupted ), "not a session" );
        System.IO.File.SetLastWriteTimeUtc( root.AppendPart( "1002" ).AppendPart( corrupted ), utcNow - lifetime - System.TimeSpan.FromHours( 1 ) );

        (await store.PurgeExpiredAsync( TestHelper.Monitor, utcNow, lifetime )).ShouldBe( 2 );

        (await store.TryReadAsync( TestHelper.Monitor, 1001, expired.SessionId )).ShouldBeNull();
        System.IO.Directory.Exists( root.AppendPart( "1001" ) ).ShouldBeFalse( "The empty actor folder is removed." );
        (await store.TryReadAsync( TestHelper.Monitor, 1002, alive.SessionId )).ShouldNotBeNull( "Its end is checked: it is alive." );
        System.IO.File.Exists( root.AppendPart( "1002" ).AppendPart( corrupted ) ).ShouldBeFalse();
        // Written now: not a candidate (it is refused when presented, and purged later).
        (await store.TryReadAsync( TestHelper.Monitor, 1003, recent.SessionId )).ShouldNotBeNull();

        // A session saved after the purge recreates its actor folder.
        await SaveAsync( 1001, utcNow.AddHours( 1 ), utcNow );
    }
}
