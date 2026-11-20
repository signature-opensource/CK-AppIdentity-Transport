using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// An Opened remote template ("MaxInstanceCount"): an unknown caller that is one of its dynamic instances becomes a
/// candidate, trusted by an approval only; the approved instance is created again at start (its identity is pinned in the
/// store) until it is removed.
/// </summary>
[TestFixture]
public class OpenedTemplateTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    Task<ApplicationIdentityService> CreateHolderAsync( string autoTrustKey, CancellationToken token )
    {
        return TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$OpenHolder";
            c["Parties:0:PartyName"] = "$OpenWorker-{Name}";
            c["Parties:0:InstanceCount"] = "0";
            c["Parties:0:MaxInstanceCount"] = "2";
            c["Parties:0:KeyManagement:AutoTrustKey"] = autoTrustKey;
        }, ConfigureFastClock, token: token );
    }

    Task<ApplicationIdentityService> CreateWorkerAsync( string name, CancellationToken token )
    {
        return TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{name}";
            c["Defaults:KeyManagement:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = "$OpenHolder";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureFastClock, token: token );
    }

    static async Task<T?> WaitForAsync<T>( Func<T?> get, int seconds, CancellationToken token ) where T : class
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( DateTime.UtcNow < deadline )
        {
            var v = get();
            if( v != null ) return v;
            await Task.Delay( 50, token );
        }
        return null;
    }

    static PeeringIssue? Issue( ApplicationIdentityService s, string fullName )
        => s.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().FirstOrDefault( i => i.FullName == fullName && i.ApprovalCode != null );

    [Test, CancelAfter( 180000 )]
    public async Task a_candidate_is_approved_created_again_at_start_and_removed_Async( CancellationToken token )
    {
        PeerStore.ClearRemoteTrust( "Test/$OpenHolder" );
        PeerStore.ClearRemoteTrust( "Test/$OpenWorker-1" );
        PeerStore.ClearRemoteTrust( "Test/$OpenWorker-3" );
        const string worker1 = "Test/$OpenWorker-1/#Dev";
        await using( var holder = await CreateHolderAsync( "Never", token ) )
        {
            holder.Remotes.ShouldBeEmpty();
            // Out of the bound: an unknown caller, no candidate.
            await using( var outOfBound = await CreateWorkerAsync( "$OpenWorker-3", token ) )
            {
                await Task.Delay( 2000, token );
                holder.Remotes.ShouldBeEmpty();
            }
            await using var worker = await CreateWorkerAsync( "$OpenWorker-1", token );
            // The caller is a candidate: a dynamic remote that waits for an approval.
            var holderIssue = await WaitForAsync( () => Issue( holder, worker1 ), 40, token );
            holderIssue.ShouldNotBeNull( "The candidate has a pending approval." );
            var candidate = holder.Remotes.Single();
            candidate.IsDynamic.ShouldBeTrue();
            candidate.Configuration.IsDynamicInstance.ShouldBeTrue();
            var pending = TransportFeatureDriver.GetHeldPendingApprovals( holder ).ShouldHaveSingleItem();
            pending.PartyFullName.ShouldBe( worker1 );
            pending.HolderFullName.ShouldBe( holder.FullName.Path );
            pending.TemplatePartyName.ShouldBe( "$OpenWorker-{Name}" );

            // Both operators enter the code (the worker must approve the holder too).
            var workerIssue = await WaitForAsync( () => Issue( worker, "Test/$OpenHolder/#Dev" ), 40, token );
            workerIssue.ShouldNotBeNull();
            holderIssue.TryApprove( TestHelper.Monitor, workerIssue.ApprovalCode! ).ShouldBeTrue();
            workerIssue.TryApprove( TestHelper.Monitor, holderIssue.ApprovalCode! ).ShouldBeTrue();
            var connected = await WaitForAsync( () => candidate.GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected ? "Connected" : null, 40, token );
            connected.ShouldNotBeNull( "The instance is approved: it connects." );

            TransportFeatureDriver.GetHeldPartyInstances( holder ).ShouldBe( [new PartyInstanceValue( worker1, holder.FullName.Path, "$OpenWorker-{Name}" )] );
        }
        // The approved instance is created again at start: its identity is pinned in the store.
        await using( var holder = await CreateHolderAsync( "Never", token ) )
        {
            var w1 = holder.Remotes.ShouldHaveSingleItem();
            w1.FullName.Path.ShouldBe( worker1 );
            w1.IsDynamic.ShouldBeTrue();
            w1.GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedEvent.ShouldNotBeNull();
            var folder = w1.SharedFileStore.FolderPath;
            (await holder.RemoveTemplateInstanceAsync( TestHelper.Monitor, w1 )).ShouldBeTrue();
            holder.Remotes.ShouldBeEmpty();
            Directory.EnumerateFiles( folder, IFileStore.TrustFilePattern ).ShouldBeEmpty();
            Directory.Exists( folder.AppendPart( "-Local" ) ).ShouldBeTrue( "The worker's own folder (the shared test store) is kept." );
        }
        await using( var holder = await CreateHolderAsync( "Never", token ) )
        {
            holder.Remotes.ShouldBeEmpty( "Removed: not created again." );
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task an_Opened_template_never_trusts_automatically_Async( CancellationToken token )
    {
        PeerStore.ClearRemoteTrust( "Test/$OpenWorker-2" );
        await using( var holder = await CreateHolderAsync( "Once", token ) )
        {
            await using var worker = await CreateWorkerAsync( "$OpenWorker-2", token );
            (await WaitForAsync( () => Issue( holder, "Test/$OpenWorker-2/#Dev" ), 40, token )).ShouldNotBeNull( "Still an approval." );
            holder.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.AutoTrustKey.ShouldBe( KeyManagement.AutoTrustKey.Never );
            holder.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedEvent.ShouldBeNull();
        }
        PeerStore.ClearRemoteTrust( "Test/$OpenWorker-2" );
    }
}
