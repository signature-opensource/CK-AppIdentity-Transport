using CK.AppIdentity.CKey.Tool;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing.AppIdentity.Cris;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.CKey.Tests;

/// <summary>
/// The ckey tool against running parties: "Test/$Sender" and "Test/$Listener" allow the "CKey" feature and don't trust
/// each other ("AutoTrustKey": "Never" on both sides: a "both approval").
/// </summary>
[TestFixture]
[NonParallelizable]
public class CKeyTests
{
    // Their own names and port: the test assemblies run in parallel (the default "Test/$Sender", "Test/$Listener" and
    // port of RunningApplication are used by the other ones).
    const int Port = 37180;

    sealed class Pair( RunningApplication sender, RunningApplication listener ) : IAsyncDisposable
    {
        public void Deconstruct( out RunningApplication a, out RunningApplication b ) => (a, b) = (sender, listener);

        public async ValueTask DisposeAsync()
        {
            await sender.DisposeAsync();
            await listener.DisposeAsync();
        }
    }

    static async Task<Pair> StartAsync()
    {
        var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: false, c =>
        {
            c["FullName"] = "Test/$CKeyListener";
            c["Local:AllowFeatures"] = "CKey";
            c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{Port}";
            c["Parties:0:PartyName"] = "$CKeySender";
            c["Parties:0:AutoTrustKey"] = "Never";
        }, null, typeof( CKeyFeatureDriver ) );
        try
        {
            var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: true, c =>
            {
                c["FullName"] = "Test/$CKeySender";
                c["Local:AllowFeatures"] = "CKey";
                c["Parties:0:PartyName"] = "$CKeyListener";
                c["Parties:0:Address"] = $"tcp:127.0.0.1:{Port}";
                c["Parties:0:AutoTrustKey"] = "Never";
            },
            // The initiator retries its connection on its heartbeat.
            RunningApplication.WithHeartBeat(),
            typeof( CKeyFeatureDriver ) );
            return new Pair( sender, listener );
        }
        catch
        {
            await listener.DisposeAsync();
            throw;
        }
    }

    // Runs the tool in-process, from a folder where no party runs (unless given).
    static async Task<(int Code, string Output, string Error)> CKeyAsync( params string[] args )
    {
        var output = new StringWriter();
        var error = new StringWriter();
        int code = await CKeyTool.RunAsync( args, output, error, _ => null, TestHelper.TestProjectFolder );
        TestHelper.Monitor.Info( $"ckey {string.Join( ' ', args )} => {code}{Environment.NewLine}{output}{error}" );
        return (code, output.ToString(), error.ToString());
    }

    static async Task<T?> WaitForAsync<T>( Func<T?> get ) where T : class
    {
        for( int i = 0; i < 300; ++i )
        {
            var v = get();
            if( v != null ) return v;
            await Task.Delay( 100 );
        }
        return null;
    }

    static PeeringIssue? IssueOf( RunningApplication app, string fullName )
        => app.ApplicationIdentityService.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().FirstOrDefault( i => i.FullName == fullName );

    static Task<string?> ConnectedAsync( RunningApplication a )
        => WaitForAsync( () => a.ApplicationIdentityService.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected ? "connected" : null );

    [Test]
    public async Task ckey_lists_the_running_parties_and_shows_the_status_of_one_Async()
    {
        await using var pair = await StartAsync();
        var (a, b) = pair;
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;

        var list = await CKeyAsync( "list" );
        list.Code.ShouldBe( 0 );
        list.Output.ShouldContain( $"Application: {aName}" );
        list.Output.ShouldContain( $"Application: {bName}" );

        // The checkpoint is the party's: ready to be the trust anchor of another party.
        (await WaitForAsync( () => IssueOf( a, bName )?.ApprovalCode )).ShouldNotBeNull();
        var status = await CKeyAsync( "status", "--party", aName );
        status.Code.ShouldBe( 0 );
        status.Output.ShouldContain( $"Checkpoint: {a.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().Checkpoint}" );
        status.Output.ShouldContain( $"- {bName}: RequiresBothApproval" );
        status.Output.ShouldContain( $"Approval code:   {IssueOf( a, bName )!.ApprovalCode}" );

        // Without --party, the party is the one that runs from the folder of the tool: none here.
        (await CKeyAsync( "status" )).Error.ShouldContain( "No party runs from the folder of this ckey" );
        // Both run from the folder of the tests (one process): ckey never picks one.
        var output = new StringWriter();
        var error = new StringWriter();
        (await CKeyTool.RunAsync( ["status"], output, error, _ => null, AppContext.BaseDirectory )).ShouldBe( 1 );
        error.ToString().ShouldContain( "2 parties run from the folder of this ckey" );

        (await CKeyAsync( "status", "--party", "Test/$Nobody/#Dev" )).Code.ShouldBe( 1 );
        (await CKeyAsync( "nonsense" )).Code.ShouldBe( 2 );
    }

    [Test]
    public async Task more_clients_than_instances_do_not_stop_the_pipe_Async()
    {
        await using var pair = await StartAsync();
        var (a, _) = pair;
        string aName = a.ApplicationIdentityService.FullName;
        var pipeName = CKeyPipeServer.GetPipeName( a.ApplicationIdentityService.FullName.Path );
        // Silent clients hold every instance of the pipe (each handler waits for its request).
        var clients = new System.Collections.Generic.List<System.IO.Pipes.NamedPipeClientStream>();
        try
        {
            for( int i = 0; i < 6; ++i )
            {
                var c = new System.IO.Pipes.NamedPipeClientStream( ".", pipeName, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous );
                clients.Add( c );
                try
                {
                    await c.ConnectAsync( 1000 );
                }
                catch( TimeoutException )
                {
                    // No instance is listening: the server waits for a handler to end.
                }
            }
            clients.Count( c => c.IsConnected ).ShouldBeGreaterThanOrEqualTo( 4 );
        }
        finally
        {
            foreach( var c in clients ) c.Dispose();
        }
        // They left: the handlers end, the pipe listens again.
        (await CKeyAsync( "status", "--party", aName )).Code.ShouldBe( 0 );
    }

    [Test]
    public async Task ckey_approve_completes_a_both_approval_on_each_side_Async()
    {
        await using var pair = await StartAsync();
        var (a, b) = pair;
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        var code = await WaitForAsync( () => IssueOf( a, bName )?.ApprovalCode );
        code.ShouldNotBeNull();
        (await WaitForAsync( () => IssueOf( b, aName )?.ApprovalCode )).ShouldBe( code, "The same code on both sides." );

        (await CKeyAsync( "approve", bName, code == "1234-5678" ? "8765-4321" : "1234-5678", "--party", aName )).Error.ShouldContain( "doesn't match" );
        (await CKeyAsync( "approve", bName, code, "--party", aName )).Code.ShouldBe( 0 );
        (await CKeyAsync( "approve", aName, code, "--party", bName )).Code.ShouldBe( 0 );
        (await ConnectedAsync( a )).ShouldNotBeNull( "Both sides approved each other: they connect." );
    }

    [Test]
    public async Task an_exported_trust_imported_on_each_side_connects_the_parties_Async()
    {
        await using var pair = await StartAsync();
        var (a, b) = pair;
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        // Out of the repository: the trust files are generated.
        var folder = new NormalizedPath( Path.Combine( Path.GetTempPath(), "CK.AppIdentity.CKey.Tests" ) );
        TestHelper.CleanupFolder( folder );
        string aFile = folder.AppendPart( "A.ckeytrust" );
        string bFile = folder.AppendPart( "B.ckeytrust" );

        // A generated password, printed once.
        var export = await CKeyAsync( "export", "trust", aFile, "--party", aName );
        export.Code.ShouldBe( 0 );
        var password = export.Output.Split( Environment.NewLine ).Single( l => l.StartsWith( "Password: " ) ).Substring( "Password: ".Length );
        password.Length.ShouldBe( 24 );

        // Refused: a wrong password, the trust of a party that is not a remote, an expired trust.
        (await CKeyAsync( "import", "trust", aFile, "--party", bName, "--pwd", "wrong" )).Error.ShouldContain( "Wrong password" );
        (await CKeyAsync( "import", "trust", aFile, "--party", aName, "--pwd", password )).Error.ShouldContain( "is not a remote" );
        var expired = TrustFile.Encrypt( new TrustFile.Content( aName, [], DateTime.UtcNow.AddHours( -1 ) ), "pwd" );
        string expiredFile = folder.AppendPart( "Expired.ckeytrust" );
        File.WriteAllBytes( expiredFile, expired );
        (await CKeyAsync( "import", "trust", expiredFile, "--party", bName, "--pwd", "pwd" )).Error.ShouldContain( "expired" );
        // Without console and without --pwd, the import fails.
        (await CKeyAsync( "import", "trust", aFile, "--party", bName )).Code.ShouldBe( 2 );

        // B trusts A; then the other way, with a given password and a short expiry: they connect.
        (await CKeyAsync( "import", "trust", aFile, "--party", bName, "--pwd", password )).Code.ShouldBe( 0 );
        (await CKeyAsync( "export", "trust", bFile, "--party", bName, "--pwd", "a-script-password", "--expires", "5m" )).Code.ShouldBe( 0 );
        (await CKeyAsync( "import", "trust", bFile, "--party", aName, "--pwd", "a-script-password" )).Code.ShouldBe( 0 );
        (await ConnectedAsync( a )).ShouldNotBeNull( "Each side trusts the other: they connect." );

        (await CKeyAsync( "export", "trust", bFile, "--party", bName, "--expires", "8d" )).Code.ShouldBe( 2, "7 days at most." );
    }

    [Test]
    public async Task a_tenant_domain_cannot_allow_CKey_Async()
    {
        await Should.ThrowAsync<Exception>( () => RunningApplication.CreateAsync( TestHelper.Monitor, isSender: false, c =>
        {
            c["FullName"] = "Test/$CKeyTenants";
            c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{Port + 1}";
            c["Parties:1:FullName"] = "Tenant/$Tenant";
            c["Parties:1:Local:AllowFeatures"] = "CKey";
            c["Parties:1:Parties:0:PartyName"] = "$X";
        }, null, typeof( CKeyFeatureDriver ) ) );
    }

    [Test]
    [Platform( "Win" )]
    public void on_Windows_the_pipe_denies_the_network_clients()
    {
#pragma warning disable CA1416 // Validate platform compatibility (Windows only).
        var rules = CKeyPipeServer.CreateWindowsSecurity().GetAccessRules( true, false, typeof( SecurityIdentifier ) )
                                                         .Cast<System.IO.Pipes.PipeAccessRule>()
                                                         .ToList();
        rules.ShouldContain( r => r.AccessControlType == AccessControlType.Deny
                                  && ((SecurityIdentifier)r.IdentityReference).IsWellKnown( WellKnownSidType.NetworkSid ) );
        rules.Where( r => r.AccessControlType == AccessControlType.Allow )
             .ShouldAllBe( r => r.IdentityReference == WindowsIdentity.GetCurrent().User );
#pragma warning restore CA1416
    }
}
