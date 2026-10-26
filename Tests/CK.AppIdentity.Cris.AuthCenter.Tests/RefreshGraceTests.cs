using CK.Auth;
using CK.Core;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// The previous secrets of a session are accepted once, in the grace window after a rotation: the answer of the
/// rotation may have been lost (<see cref="AuthCenterOptions.RefreshGraceWindow"/>).
/// </summary>
[TestFixture]
public class RefreshGraceTests
{
    static Task<ISessionResult> RefreshAsync( AuthCenterApp app ) => app.ExecuteSessionAsync( p => p.Create<IRefreshSessionCommand>() );

    static async Task<AuthCenterSession?> ReadSessionAsync( AuthCenterApp app, string sessionKey )
    {
        AuthCenterSession.TryParseSessionKey( sessionKey, out var actorId, out var sessionId ).ShouldBeTrue();
        return await app.Center.Local.ShouldNotBeNull().Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId );
    }

    // Logs in Albert and refreshes: returns the secrets of the login (now the previous ones) and the current ones.
    static async Task<(AuthenticationSessionProof Previous, AuthenticationSessionProof Current)> LoginAndRefreshAsync( AuthCenterApp app )
    {
        await app.LoginAsync( "Albert" );
        var previous = app.Caller.Cookies.ShouldNotBeNull();
        (await RefreshAsync( app )).Success.ShouldBeTrue();
        return (previous, app.Caller.Cookies.ShouldNotBeNull());
    }

    [Test]
    public async Task the_grace_window_is_1_minute_by_default_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        app.Center.Local.ShouldNotBeNull().Options.RefreshGraceWindow.ShouldBe( TimeSpan.FromMinutes( 1 ) );
        AuthCenterOptions.MaxRefreshGraceWindow.ShouldBe( TimeSpan.FromMinutes( 5 ) );
    }

    [Test]
    public async Task a_lost_refresh_answer_is_recovered_with_the_previous_secrets_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var (c0, c1) = await LoginAndRefreshAsync( app );

        // The answer of the refresh is lost: the caller still has the login's secrets.
        app.Caller.Cookies = c0;
        (await RefreshAsync( app )).Success.ShouldBeTrue( "The previous secrets are accepted once." );
        var c2 = app.Caller.Cookies.ShouldNotBeNull();
        var s = (await ReadSessionAsync( app, c2.SessionKey )).ShouldNotBeNull();
        s.Matches( c2 ).ShouldBeTrue();
        s.PreviousRefreshSecretHash.ShouldBeNull( "Used: the previous secrets are cleared." );
        (await RefreshAsync( app )).Success.ShouldBeTrue( "The session goes on." );

        // The secrets whose answer was lost are orphaned: if someone presents them, it is a reuse.
        app.Caller.Cookies = c1;
        (await RefreshAsync( app )).Success.ShouldBeFalse();
        (await ReadSessionAsync( app, c2.SessionKey )).ShouldBeNull( "The session is revoked." );
    }

    [Test]
    public async Task the_previous_secrets_are_accepted_once_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var (c0, _) = await LoginAndRefreshAsync( app );
        app.Caller.Cookies = c0;
        (await RefreshAsync( app )).Success.ShouldBeTrue();
        var key = app.Caller.Cookies.ShouldNotBeNull().SessionKey;

        // A second use of the same previous secrets is a reuse: the session is revoked.
        app.Caller.Cookies = c0;
        var r = await RefreshAsync( app );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.InvalidSession" );
        (await ReadSessionAsync( app, key )).ShouldBeNull();
    }

    [Test]
    public async Task outside_the_grace_window_the_previous_secrets_revoke_the_session_Async()
    {
        await using var app = await AuthCenterApp.StartAsync( c =>
        {
            AuthCenterApp.LocalAuthCenter( c );
            c["AuthCenter:RefreshGraceWindow"] = "00:00:00.300";
        } );
        var (c0, c1) = await LoginAndRefreshAsync( app );
        await Task.Delay( 400 );
        app.Caller.Cookies = c0;
        (await RefreshAsync( app )).Success.ShouldBeFalse();
        (await ReadSessionAsync( app, c1.SessionKey )).ShouldBeNull( "The session is revoked." );
    }

    [Test]
    public async Task an_operation_that_does_not_rotate_refuses_the_previous_secrets_without_revoking_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var (c0, _) = await LoginAndRefreshAsync( app );
        app.Caller.Cookies = c0;
        await using( var scope = app.Services.Services.CreateAsyncScope() )
        {
            var (session, error, errorId) = await scope.ServiceProvider.GetRequiredService<AuthCenterSessionService>().GetCriticalSessionAsync( TestHelper.Monitor );
            session.ShouldBeNull();
            errorId.ShouldBe( "Authentication.InvalidSession" );
        }
        (await ReadSessionAsync( app, c0.SessionKey )).ShouldNotBeNull( "Not revoked." );
        (await RefreshAsync( app )).Success.ShouldBeTrue( "The previous secrets can still recover the session." );
    }

    [Test]
    public async Task logout_accepts_the_previous_secrets_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var (c0, _) = await LoginAndRefreshAsync( app );
        app.Caller.Cookies = c0;
        await app.ExecuteAsync( p => p.Create<ILogoutSessionCommand>() );
        (await ReadSessionAsync( app, c0.SessionKey )).ShouldBeNull( "The session is ended." );
    }

    [Test]
    public async Task a_version_1_session_file_has_no_previous_secrets_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var store = app.Center.Local.ShouldNotBeNull().Sessions;
        var sessionId = AuthCenterSession.NewSessionId();
        var folder = app.Identity.LocalFileStore.FolderPath.Combine( "AuthCenter/Sessions/1004" );
        Directory.CreateDirectory( folder );
        File.WriteAllText( folder.AppendPart( sessionId ), $$"""
            {"Version":1,"SessionId":"{{sessionId}}","ActualActorId":1004,"ActorId":1004,"Created":"2026-10-26T10:00:00Z",
             "Expires":"2126-10-26T10:00:00Z","RememberMe":false,"DeviceId":"D","RefreshSecretHash":"r","BindingSecretHash":"b"}
            """ );
        var s = (await store.TryReadAsync( TestHelper.Monitor, 1004, sessionId )).ShouldNotBeNull();
        s.PreviousRefreshSecretHash.ShouldBeNull();
        s.PreviousBindingSecretHash.ShouldBeNull();
        s.RotatedAt.ShouldBe( DateTime.MinValue );

        // Saved again, it is a version 2 file that keeps the rotation.
        var rotated = s.Rotate( "r2", "b2", DateTime.UtcNow, fromPrevious: false );
        await store.SaveAsync( rotated );
        var read = (await store.TryReadAsync( TestHelper.Monitor, 1004, sessionId )).ShouldNotBeNull();
        read.PreviousRefreshSecretHash.ShouldBe( "r" );
        read.PreviousBindingSecretHash.ShouldBe( "b" );
        read.RefreshSecretHash.ShouldBe( "r2" );
        store.TryDelete( TestHelper.Monitor, 1004, sessionId );
    }

    [Test]
    public async Task the_operations_on_a_session_are_serialized_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var store = app.Center.Local.ShouldNotBeNull().Sessions;
        var first = await store.LockAsync( "1.session" );
        var second = store.LockAsync( "1.session" ).AsTask();
        var other = store.LockAsync( "2.session" ).AsTask();
        (await other).Dispose();
        await Task.Delay( 50 );
        second.IsCompleted.ShouldBeFalse( "The same session waits." );
        first.Dispose();
        (await second).Dispose();
    }
}
