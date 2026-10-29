using CK.Testing;
using CK.AppIdentity.Cris.AuthCenter.Passkey;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.IO.Authentication.Passkey;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// The passkey logins of a local AuthCenter (<see cref="AuthCenterPasskey"/>, <see cref="AuthCenterPasskeyHandlers"/>)
/// with a <see cref="SoftAuthenticator"/>: real WebAuthn data, verified by Fido2NetLib.
/// </summary>
[TestFixture]
public class PasskeyTests
{
    static void Configuration( MutableConfigurationSection c )
    {
        AuthCenterApp.LocalAuthCenter( c );
        c["Local:AuthCenter:Passkey:RpId"] = "example.com";
        c["Local:AuthCenter:Passkey:Origins:0"] = "https://front.example.com";
    }

    static Task<AuthCenterApp> StartAsync() => AuthCenterApp.StartAsync( Configuration, withPasskeys: true );

    static InMemoryPasskeyStore Store( AuthCenterApp app ) => app.Services.Services.GetRequiredService<InMemoryPasskeyStore>();

    static IEnumerable<string> Errors( object? result ) => result.ShouldBeAssignableTo<ICrisResultError>().ShouldNotBeNull().Errors.Select( e => e.Text );

    // Albert logs in (a Critical session) and registers the authenticator.
    static async Task RegisterAsync( AuthCenterApp app, SoftAuthenticator authenticator )
    {
        (await app.LoginAsync( "Albert" )).Info.UnsafeActualActor.Level.ShouldBe( AuthLevel.Critical );
        var options = (await app.ExecuteAsync( p => p.Create<IStartPasskeyRegistrationCommand>( c => c.Name = "My phone" ) )).ShouldBeOfType<string>();
        var r = (IPasskeyRegistrationResult)(await app.ExecuteAsync( p => p.Create<IPasskeyRegistrationCommand>( c => c.Response = authenticator.Create( options ) ) )).ShouldNotBeNull();
        r.Success.ShouldBeTrue();
        r.Name.ShouldBe( "My phone" );
    }

    static async Task<string> StartLoginAsync( AuthCenterApp app ) => (await app.ExecuteAsync( p => p.Create<IStartPasskeyLoginCommand>() )).ShouldBeOfType<string>();

    static Task<ISessionResult> LoginAsync( AuthCenterApp app, string response )
    {
        return app.ExecuteSessionAsync( p => p.Create<IPasskeyLoginCommand>( c => { c.Response = response; c.RememberMe = true; } ) );
    }

    [Test]
    public async Task a_registered_passkey_logs_in_at_the_Critical_level_Async()
    {
        await using var app = await StartAsync();
        using var authenticator = new SoftAuthenticator();
        await RegisterAsync( app, authenticator );

        var stored = Store( app ).All.ShouldHaveSingleItem();
        stored.ActorId.ShouldBe( 3712 );
        stored.Name.ShouldBe( "My phone" );
        stored.CredentialId.ToArray().ShouldBe( authenticator.CredentialId.ToArray() );
        stored.BackupEligible.ShouldBeTrue();
        stored.Transports.ShouldBe( ["internal", "hybrid"] );

        // The login is usernameless: no credential is listed, the user must be verified.
        var options = JsonNode.Parse( await StartLoginAsync( app ) )!;
        options["rpId"]!.GetValue<string>().ShouldBe( "example.com" );
        options["userVerification"]!.GetValue<string>().ShouldBe( "required" );
        (options["allowCredentials"] is null || options["allowCredentials"]!.AsArray().Count == 0).ShouldBeTrue();

        var r = await LoginAsync( app, authenticator.Get( options.ToJsonString() ) );
        r.Success.ShouldBeTrue();
        r.RememberMe.ShouldBeTrue();
        r.Info.UnsafeActor.ActorName.ShouldBe( "Albert" );
        r.Info.UnsafeActor.Level.ShouldBe( AuthLevel.Critical );
        Store( app ).All.Single().SignCount.ShouldBe( 0u, "A synchronized passkey (counter always 0) is accepted." );
    }

    [Test]
    public async Task the_scheme_is_listed_when_configured_with_a_store_Async()
    {
        await using( var app = await StartAsync() )
        {
            var schemes = (IList<ILoginSchemeInfo>)(await app.ExecuteAsync( p => p.Create<IGetLoginSchemesQCommand>() )).ShouldNotBeNull();
            schemes.Single( s => s.Name == "Passkey" ).CriticalLifetime.ShouldBe( TimeSpan.FromMinutes( 5 ), "The default CriticalLifetime." );
        }
        // Installed but not configured: the family hides its provider name.
        await using( var app = await AuthCenterApp.StartAsync( withPasskeys: true ) )
        {
            var schemes = (IList<ILoginSchemeInfo>)(await app.ExecuteAsync( p => p.Create<IGetLoginSchemesQCommand>() )).ShouldNotBeNull();
            schemes.Select( s => s.Name ).ShouldNotContain( "Passkey" );
            Errors( await app.ExecuteAsync( p => p.Create<IStartPasskeyLoginCommand>() ) ).ShouldContain( "Passkeys are not available." );
        }
    }

    [Test]
    public async Task the_endpoint_origin_must_be_configured_Async()
    {
        await using var app = await StartAsync();
        app.Caller.WebOrigin = "https://other.example.com";
        Errors( await app.ExecuteAsync( p => p.Create<IStartPasskeyLoginCommand>() ) ).ShouldContain( "The origin 'https://other.example.com' is not allowed for passkeys." );
        app.Caller.WebOrigin = null;
        Errors( await app.ExecuteAsync( p => p.Create<IStartPasskeyLoginCommand>() ) ).ShouldContain( "Passkeys require an endpoint that serves web pages.", "Refused by the receiving endpoint." );
    }

    [Test]
    public async Task the_signed_origin_and_relying_party_are_checked_Async()
    {
        await using var app = await StartAsync();
        using var authenticator = new SoftAuthenticator();
        await RegisterAsync( app, authenticator );

        // A phishing page: the browser signs its own origin.
        authenticator.Origin = "https://evil.example.net";
        var r = await LoginAsync( app, authenticator.Get( await StartLoginAsync( app ) ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.PasskeyVerificationFailed" );

        // Another relying party.
        authenticator.Origin = "https://front.example.com";
        authenticator.RpId = "evil.com";
        r = await LoginAsync( app, authenticator.Get( await StartLoginAsync( app ) ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.PasskeyVerificationFailed" );

        authenticator.RpId = null;
        (await LoginAsync( app, authenticator.Get( await StartLoginAsync( app ) ) )).Success.ShouldBeTrue();
    }

    [Test]
    public async Task the_user_must_be_verified_Async()
    {
        await using var app = await StartAsync();
        using var authenticator = new SoftAuthenticator();
        await RegisterAsync( app, authenticator );

        authenticator.UserVerified = false;
        var r = await LoginAsync( app, authenticator.Get( await StartLoginAsync( app ) ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.PasskeyVerificationFailed" );

        // At registration too.
        using var other = new SoftAuthenticator { UserVerified = false };
        var options = (await app.ExecuteAsync( p => p.Create<IStartPasskeyRegistrationCommand>() )).ShouldBeOfType<string>();
        var reg = (IPasskeyRegistrationResult)(await app.ExecuteAsync( p => p.Create<IPasskeyRegistrationCommand>( c => c.Response = other.Create( options ) ) )).ShouldNotBeNull();
        reg.Success.ShouldBeFalse();
        Store( app ).All.Count.ShouldBe( 1 );
    }

    [Test]
    public async Task a_challenge_is_used_once_and_an_unknown_passkey_is_refused_Async()
    {
        await using var app = await StartAsync();
        using var authenticator = new SoftAuthenticator();
        await RegisterAsync( app, authenticator );

        var response = authenticator.Get( await StartLoginAsync( app ) );
        (await LoginAsync( app, response )).Success.ShouldBeTrue();
        var replay = await LoginAsync( app, response );
        replay.Success.ShouldBeFalse();
        replay.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.PasskeyCeremonyExpired" );

        using var unknown = new SoftAuthenticator();
        unknown.Create( (await app.ExecuteAsync( p => p.Create<IStartPasskeyRegistrationCommand>() )).ShouldBeOfType<string>() );
        var r = await LoginAsync( app, unknown.Get( await StartLoginAsync( app ) ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.UnknownPasskey" );
    }

    [Test]
    public async Task a_signature_counter_regression_is_refused_Async()
    {
        await using var app = await StartAsync();
        using var authenticator = new SoftAuthenticator { SignCount = 10 };
        await RegisterAsync( app, authenticator );

        (await LoginAsync( app, authenticator.Get( await StartLoginAsync( app ) ) )).Success.ShouldBeTrue();
        Store( app ).All.Single().SignCount.ShouldBe( 11u );

        // A clone of the authenticator, behind.
        authenticator.SignCount = 5;
        var r = await LoginAsync( app, authenticator.Get( await StartLoginAsync( app ) ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.PasskeyVerificationFailed" );
    }

    [Test]
    public async Task registering_requires_the_Critical_level_and_the_same_session_Async()
    {
        await using var app = await StartAsync();
        using var authenticator = new SoftAuthenticator();

        // A weak actor is Unsafe.
        await app.LoginAsync( "Operator" );
        Errors( await app.ExecuteAsync( p => p.Create<IStartPasskeyRegistrationCommand>() ) ).ShouldContain( "This requires the Critical level." );

        // Started in one session, completed in another one.
        await app.LoginAsync( "Albert" );
        var options = (await app.ExecuteAsync( p => p.Create<IStartPasskeyRegistrationCommand>() )).ShouldBeOfType<string>();
        await app.LoginAsync( "Albert" );
        var r = (IPasskeyRegistrationResult)(await app.ExecuteAsync( p => p.Create<IPasskeyRegistrationCommand>( c => c.Response = authenticator.Create( options ) ) )).ShouldNotBeNull();
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.PasskeyCeremonyMismatch" );
        Store( app ).All.ShouldBeEmpty();

        // A login response cannot complete a registration.
        options = (await app.ExecuteAsync( p => p.Create<IStartPasskeyRegistrationCommand>() )).ShouldBeOfType<string>();
        authenticator.Create( options );
        r = (IPasskeyRegistrationResult)(await app.ExecuteAsync( p => p.Create<IPasskeyRegistrationCommand>( c => c.Response = authenticator.Get( StartLoginOptionsFrom( options ) ) ) )).ShouldNotBeNull();
        r.Success.ShouldBeFalse();
    }

    // Login options with the challenge of registration options (a cross-ceremony replay).
    static string StartLoginOptionsFrom( string registrationOptions )
    {
        var o = JsonNode.Parse( registrationOptions )!;
        return new JsonObject { ["challenge"] = o["challenge"]!.GetValue<string>(), ["rpId"] = o["rp"]!["id"]!.GetValue<string>() }.ToJsonString();
    }

    [Test]
    public void the_options_are_checked()
    {
        AuthCenterPasskeyOptions.NormalizeOrigin( "https://Front.Example.com:443" ).ShouldBe( "https://front.example.com" );
        AuthCenterPasskeyOptions.NormalizeOrigin( "http://localhost:5000" ).ShouldBe( "http://localhost:5000" );
        AuthCenterPasskeyOptions.NormalizeOrigin( "http://front.example.com" ).ShouldBeNull( "https only (http on a loopback)." );
        AuthCenterPasskeyOptions.NormalizeOrigin( "https://front.example.com/path" ).ShouldBeNull();
    }

    [Test]
    public void the_pending_store_is_bounded_one_use_and_expiring()
    {
        var store = new AuthCenterPendingStore<string>( TimeSpan.FromMinutes( 1 ), 2 );
        var now = DateTime.UtcNow;
        store.TryAdd( "a", "A", now ).ShouldBeTrue();
        store.TryAdd( "b", "B", now ).ShouldBeTrue();
        store.TryAdd( "c", "C", now ).ShouldBeFalse( "Full." );
        store.TryTake( "a", now, out var expired ).ShouldBe( "A" );
        expired.ShouldBeFalse();
        store.TryTake( "a", now, out _ ).ShouldBeNull( "One use." );
        store.TryTake( "b", now.AddMinutes( 2 ), out expired ).ShouldBeNull();
        expired.ShouldBeTrue();
        store.TryAdd( "c", "C", now.AddMinutes( 2 ) ).ShouldBeTrue( "Room again." );
    }
}
