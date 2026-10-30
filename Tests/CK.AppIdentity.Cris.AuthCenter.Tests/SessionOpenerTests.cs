using CK.Testing;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// The local AuthCenter: a login operation is issued by the <see cref="AuthCenterSessionIssuer"/>.
/// </summary>
[TestFixture]
public class SessionOpenerTests
{
    [Test]
    public async Task a_login_opens_a_session_and_returns_a_signed_token_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var center = app.Center;
        app.LocalCenter.Options.TokenLifetime.ShouldBe( TimeSpan.FromMinutes( 2 ) );

        var r = await app.LoginAsync( "Operator" );
        r.Success.ShouldBeTrue();
        r.RememberMe.ShouldBeFalse( "The Weak login handler never remembers (the OIDC and Basic tests remember)." );
        r.Info.UnsafeActor.ActorId.ShouldBe( 42 );
        r.Info.UnsafeActor.Level.ShouldBe( AuthLevel.Unsafe );
        r.Info.DeviceId.ShouldNotBeNullOrEmpty();
        var issued = app.Caller.Issued.ShouldHaveSingleItem();
        issued.RememberMe.ShouldBeFalse();

        // The token is read back by the AuthCenter (this is what a front does): it holds the session.
        var (info, sessionId, bindingHash) = (await center.ReadTokenAsync( TestHelper.Monitor, r.Token.ShouldNotBeNull(), DateTime.UtcNow )).ShouldNotBeNull();
        info.UnsafeActor.ActorId.ShouldBe( 42 );
        info.UnsafeActor.ActorName.ShouldBe( "Operator" );
        info.UnsafeActor.Level.ShouldBe( AuthLevel.Unsafe );
        info.DeviceId.ShouldBe( r.Info.DeviceId );
        info.Expires.ShouldNotBeNull().ShouldBeLessThanOrEqualTo( DateTime.UtcNow.AddMinutes( 2 ), "The authentication cannot outlive the token." );

        // The session is stored with the hashes of the endpoint secrets, the endpoint keeps the session key.
        var session = (await app.LocalCenter.Sessions.TryReadAsync( TestHelper.Monitor, 42, sessionId )).ShouldNotBeNull();
        issued.SessionKey.ShouldBe( session.SessionKey );
        session.RefreshSecretHash.ShouldBe( "refresh-hash-1" );
        session.BindingSecretHash.ShouldBe( "binding-hash-1" );
        session.RememberMe.ShouldBeFalse();
        session.Expires.ShouldBe( issued.RefreshExpires );
        session.Matches( app.Caller.Cookies.ShouldNotBeNull() ).ShouldBeTrue();
        bindingHash.ShouldBe( session.BindingSecretHash, "The token is bound to the binding secret of its session." );

        // The endpoints read the tokens through IAuthenticationTokenReader.
        await using( var scope = app.Services.Services.CreateAsyncScope() )
        {
            var reader = scope.ServiceProvider.GetRequiredService<CK.Auth.IAuthenticationTokenReader>();
            var data = (await reader.ReadTokenAsync( TestHelper.Monitor, r.Token )).ShouldNotBeNull();
            data.Info.UnsafeActor.ActorId.ShouldBe( 42 );
            data.BindingSecretHash.ShouldBe( session.BindingSecretHash );
            (await reader.ReadTokenAsync( TestHelper.Monitor, "not a token" )).ShouldBeNull();
        }
    }

    [Test]
    public async Task the_user_data_of_the_login_command_reach_the_login_context_Async()
    {
        await using var app = await AuthCenterApp.StartAsync( recordLogins: true );

        AuthCenterApp.RecordingLoginValidator.LastUserData = null;
        var r = await app.ExecuteSessionAsync( p => p.Create<CK.IO.Authentication.Weak.IWeakLoginCommand>( c =>
        {
            c.WeakActorName = "Operator";
            c.UserData.Add( "InvitationToken", "T" );
        } ) );
        r.Success.ShouldBeTrue();
        AuthCenterApp.RecordingLoginValidator.LastUserData.ShouldNotBeNull()["InvitationToken"].ShouldBe( "T" );

        // No user data: empty, never null.
        await app.LoginAsync( "Operator" );
        AuthCenterApp.RecordingLoginValidator.LastUserData.ShouldNotBeNull().ShouldBeEmpty();
    }

    [Test]
    public async Task a_failed_login_opens_nothing_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var r = await app.LoginAsync( "Nobody" );
        r.Success.ShouldBeFalse();
        r.Token.ShouldBeNull();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.LoginFailed" );
        app.Caller.Issued.ShouldBeEmpty();
    }

    [Test]
    public async Task an_AuthCenter_application_is_its_own_AuthCenter_Async()
    {
        // An application has one role: with CK.AppIdentity.Cris.AuthCenter.Local, a local party that allows "AuthCenter" is
        // its own AuthCenter, and a remote that allows "AuthCenterRemote" is one of its remotes (never its AuthCenter).
        await using var app = await AuthCenterApp.StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Local:AllowFeatures"] = "AuthCenter";
            c["Parties:0:PartyName"] = "Front";
            c["Parties:0:AllowFeatures"] = "AuthCenterRemote";
        } );
        app.Center.AuthCenter.ShouldBeSameAs( app.Identity );
        app.Identity.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeSameAs( app.Center );
    }

    [Test]
    public async Task tokens_are_bound_to_their_local_party_and_cannot_be_tampered_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var root = app.Center;
        var acme = app.Identity.TenantDomains.Single().GetRequiredFeature<CrisAuthCenter>();
        app.Identity.TenantDomains.Single().GetFeature<LocalAuthCenter>().ShouldNotBeNull( "This application is the AuthCenter of the tenant too." );

        // An impersonation at Critical level: everything goes through the token.
        var utcNow = DateTime.UtcNow;
        var auth = AuthenticationInfo.Create( AuthCenterApp.Albert, AuthCenterApp.Robert, utcNow.AddDays( 1 ), utcNow.AddHours( 1 ), "Device", utcNow );
        var sessionId = AuthCenterSession.NewSessionId();
        var token = app.LocalCenter.CreateToken( sessionId, "the-binding-hash", auth, utcNow );

        var (info, readId, readBinding) = (await root.ReadTokenAsync( TestHelper.Monitor, token, utcNow )).ShouldNotBeNull();
        readBinding.ShouldBe( "the-binding-hash" );
        readId.ShouldBe( sessionId );
        info.IsImpersonated.ShouldBeTrue();
        info.UnsafeActualActor.ActorName.ShouldBe( "Albert" );
        info.UnsafeActor.ActorName.ShouldBe( "Robert" );
        info.Actor.Level.ShouldBe( AuthLevel.Critical );
        info.CriticalExpires.ShouldNotBeNull().ShouldBeLessThanOrEqualTo( utcNow.AddMinutes( 2 ), "Clamped by the token (2 minutes)." );

        (await acme.ReadTokenAsync( TestHelper.Monitor, token, utcNow )).ShouldBeNull( "Another local party: other keys, other audience." );

        var bytes = System.Buffers.Text.Base64Url.DecodeFromChars( token );
        bytes[10] ^= 1;
        (await root.ReadTokenAsync( TestHelper.Monitor, System.Buffers.Text.Base64Url.EncodeToString( bytes ), utcNow )).ShouldBeNull();
        (await root.ReadTokenAsync( TestHelper.Monitor, "not a token", utcNow )).ShouldBeNull();
        (await root.ReadTokenAsync( TestHelper.Monitor, token, utcNow.AddMinutes( 3 ) )).ShouldBeNull( "Expired." );
    }
}
