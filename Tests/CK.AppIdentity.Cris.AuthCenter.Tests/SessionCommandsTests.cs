using CK.Core;
using CK.IO.Authentication;
using NUnit.Framework;
using Shouldly;
using System.Collections.Generic;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// The session commands of a local AuthCenter (<see cref="AuthCenterSessionService"/>).
/// </summary>
[TestFixture]
public class SessionCommandsTests
{
    static Task<ISessionResult> RefreshAsync( AuthCenterApp app ) => app.ExecuteSessionAsync( p => p.Create<IRefreshSessionCommand>() );

    static async Task<AuthCenterSession?> ReadSessionAsync( AuthCenterApp app )
    {
        var key = app.Caller.Issued[^1].SessionKey;
        AuthCenterSession.TryParseSessionKey( key, out var actorId, out var sessionId ).ShouldBeTrue();
        return await app.Center.Local.ShouldNotBeNull().Sessions.TryReadAsync( TestHelper.Monitor, actorId, sessionId );
    }

    [Test]
    public async Task refresh_rotates_the_secrets_and_a_replayed_secret_revokes_the_session_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
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
        var schemes = (IList<string>)(await app.ExecuteAsync( p => p.Create<IGetLoginSchemesQCommand>() )).ShouldNotBeNull();
        schemes.ShouldBe( ["Weak"] );
    }
}
