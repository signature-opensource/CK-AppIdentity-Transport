using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.Cris.AspNet;
using CK.Cris.AspNet.Authentication;
using CK.IO.Authentication;
using CK.Poco.Exc.Json;
using CK.Testing;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;
using BasicLoginCommand = CK.IO.Authentication.Basic.IBasicLoginCommand;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// Requires the Normal level: answers the name of the actor.
/// </summary>
public interface INormalWhoAmIQCommand : ICommand<string>, ICommandAuthNormal
{
}

public sealed class NormalWhoAmIHandler : ISingletonAutoService
{
    [CommandHandler]
    public string Handle( INormalWhoAmIQCommand c, AuthenticationInfo info ) => info.Actor.ActorName;
}

/// <summary>
/// One application that is both the Authentication Center (CK.AppIdentity.Cris.AuthCenter.Local) and the HTTP front
/// (CK.Cris.AspNet.Authentication): the session commands received over HTTP are executed by the real HTTP endpoint and
/// their operations are handled here. Only the login provider and the actors are fakes (a real application uses its
/// database packages, like CK.DB.User.UserPassword).
/// </summary>
[TestFixture]
public class SingleApplicationTests
{
    static async Task<RunningAspNetServer> StartAsync()
    {
        var engine = TestHelper.CreateDefaultEngineConfiguration();
        engine.FirstBinPath.Types.Add( typeof( ApplicationIdentityService ),
                                       typeof( CurrentLocalParty ),
                                       typeof( CurrentLocalPartyDefaultProvider ),
                                       typeof( KeyManagementFeatureDriver ),
                                       typeof( DefaultCoreKeyStore ),
                                       typeof( AuthCenterFeatureDriver ),
                                       typeof( LocalAuthCenterFeatureDriver ),
                                       // The HTTP front.
                                       typeof( CrisAspNetService ),
                                       typeof( CrisAspNetAuthenticationPackage ),
                                       // The endpoint side and the operations, handled here.
                                       typeof( IAuthenticationSessionOpener ),
                                       typeof( AuthenticationSessionEndpointService ),
                                       typeof( AuthenticationSessionHandlers ),
                                       typeof( AuthCenterOperationHandlers ),
                                       typeof( AuthCenterCommandHandlers ),
                                       typeof( ISessionOperationResult ),
                                       typeof( IOpenSessionOperationCommand ),
                                       typeof( IRefreshSessionOperationCommand ),
                                       typeof( ILogoutSessionOperationCommand ),
                                       typeof( IImpersonateOperationCommand ),
                                       typeof( IClearImpersonationOperationCommand ),
                                       typeof( IStartRemoteLoginOperationCommand ),
                                       typeof( ICompleteRemoteLoginOperationCommand ),
                                       typeof( IAuthenticationTokenReader ),
                                       typeof( AuthCenterTokenReader ),
                                       typeof( IAuthenticationSessionEndpoint ),
                                       typeof( CrisAuthenticationService ),
                                       typeof( AuthenticationInfo ),
                                       typeof( AuthenticationInfoDefaultProvider ),
                                       typeof( AuthCenterApp.FakeActors ),
                                       typeof( AuthCenterApp.FakeBasicLoginProvider ),
                                       typeof( BasicLoginHandler ),
                                       typeof( BasicLoginCommand ),
                                       typeof( NormalizedCultureInfoAmbientServiceDefault ),
                                       typeof( TranslationService ),
                                       typeof( NormalizedCultureInfo ),
                                       typeof( CurrentCultureInfo ),
                                       typeof( IStartLoginCommand ),
                                       typeof( IRemoteLoginCallbackCommand ),
                                       typeof( RawCrisExecutor ),
                                       typeof( CrisDirectory ),
                                       typeof( ICrisResultError ),
                                       typeof( IRefreshSessionCommand ),
                                       typeof( ILogoutSessionCommand ),
                                       typeof( IImpersonateCommand ),
                                       typeof( IClearImpersonationCommand ),
                                       typeof( IGetLoginSchemesQCommand ),
                                       typeof( ILoginSchemeInfo ),
                                       typeof( ISessionResult ),
                                       typeof( IAuthenticationInfoPoco ),
                                       typeof( IActorInfoPoco ),
                                       typeof( CK.Cris.AmbientValues.AmbientValuesService ),
                                       typeof( IAuthAmbientValues ),
                                       typeof( ICultureAmbientValues ),
                                       typeof( INormalWhoAmIQCommand ),
                                       typeof( NormalWhoAmIHandler ) );
        // The HTTP front reads only the commands of the TypeScript set ("TypeFilterName").
        engine.FirstBinPath.EnsureTypeScriptConfigurationAspect( TestHelper.GetTypeScriptInlineTargetProjectPath(),
                                                                 typeof( BasicLoginCommand ),
                                                                 typeof( IRefreshSessionCommand ),
                                                                 typeof( ILogoutSessionCommand ),
                                                                 typeof( INormalWhoAmIQCommand ) );
        var map = (await engine.RunSuccessfullyAsync()).LoadMap();
        var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, AuthCenterApp.LocalAuthCenter ).ShouldNotBeNull();
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton( c );
        builder.Services.AddSingleton<IDataProtectionProvider>( FakeProtector.Fake );
        builder.Services.AddCrisAuthentication();
        var server = await builder.CreateRunningAspNetServerAsync( map, app =>
        {
            app.UseCrisAuthentication();
            app.UseCris();
        } );
        await server.Services.GetRequiredService<ApplicationIdentityService>().InitializationTask;
        return server;
    }

    static string ToJson( RunningAspNetServer server, IPoco command )
    {
        var w = new ArrayBufferWriter<byte>();
        server.Services.GetRequiredService<PocoDirectory>()
              .WriteJson( w, command, withType: true, new PocoJsonExportOptions { TypeFilterName = "TypeScript", UseCamelCase = true } );
        return Encoding.UTF8.GetString( w.WrittenSpan );
    }

    static async Task<ICrisCallResult> PostAsync( RunningAspNetServer server, string path, IPoco command )
    {
        var r = await server.Client.PostJsonAsync( path + "?UsePascalCase", ToJson( server, command ) );
        r.StatusCode.ShouldBe( HttpStatusCode.OK );
        return server.Services.GetRequiredService<PocoDirectory>().Find<ICrisCallResult>()!.ReadJson( await r.Content.ReadAsByteArrayAsync() ).ShouldNotBeNull();
    }

    // A refused call: its result is an ICrisResultError whose user messages are in the simplified format of the
    // TypeScript set, that the Json import cannot read back: the response is checked as text.
    static async Task<string> PostRefusedAsync( RunningAspNetServer server, string path, IPoco command )
    {
        var r = await server.Client.PostJsonAsync( path + "?UsePascalCase", ToJson( server, command ) );
        r.StatusCode.ShouldBe( HttpStatusCode.OK );
        var text = await r.Content.ReadAsStringAsync();
        text.ShouldContain( "CrisResultError" );
        return text;
    }

    static T Create<T>( RunningAspNetServer server, Action<T>? configure = null ) where T : class, IPoco
        => server.Services.GetRequiredService<PocoDirectory>().Create( configure ?? (_ => { }) );

    [Test]
    public async Task the_AuthCenter_and_its_HTTP_front_in_one_application_Async()
    {
        await using var server = await StartAsync();

        // Anonymous: the Normal command is refused.
        await PostRefusedAsync( server, "/.cris", Create<INormalWhoAmIQCommand>( server, c => c.ActorId = 0 ) );

        // A Basic login over HTTP: executed by the HTTP endpoint, its operation by the local AuthCenter.
        var login = (ISessionResult)(await PostAsync( server, "/.cris/auth", Create<BasicLoginCommand>( server, c => { c.UserName = "Albert"; c.Password = "secret"; } ) ))
                                        .Result.ShouldNotBeNull();
        login.Success.ShouldBeTrue();
        login.Info.UnsafeActor.ActorName.ShouldBe( "Albert" );
        login.Token.ShouldNotBeNull();

        // The token (read by the local AuthCenter) with the binding cookie: the Normal command is accepted.
        server.Client.Token = login.Token;
        (await PostAsync( server, "/.cris", Create<INormalWhoAmIQCommand>( server, c => c.ActorId = 3712 ) )).Result.ShouldBe( "Albert" );

        // The refresh (the refresh cookie) rotates the session.
        var refreshed = (ISessionResult)(await PostAsync( server, "/.cris/auth", Create<IRefreshSessionCommand>( server ) )).Result.ShouldNotBeNull();
        refreshed.Success.ShouldBeTrue();
        refreshed.Token.ShouldNotBeNull().ShouldNotBe( login.Token );
        server.Client.Token = refreshed.Token;
        (await PostAsync( server, "/.cris", Create<INormalWhoAmIQCommand>( server, c => c.ActorId = 3712 ) )).Result.ShouldBe( "Albert" );

        // The logout clears the cookies: the token is useless.
        await PostAsync( server, "/.cris/auth", Create<ILogoutSessionCommand>( server ) );
        await PostRefusedAsync( server, "/.cris", Create<INormalWhoAmIQCommand>( server, c => c.ActorId = 3712 ) );
    }
}
