using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// The PartyActor identifiers of a remote of an AuthCenter: asked to the AuthCenter on connection
/// (<see cref="IGetPartyActorIdsQCommand"/>), that has them from its registrar (CK.DB.AppIdentity, faked here).
/// </summary>
[TestFixture]
public class PartyActorIdsTests
{
    /// <summary>
    /// Stands for the CK.DB.AppIdentity registrar (the AuthCenter tests have no database): the PartyActors of a shared
    /// "actors database", by full name.
    /// </summary>
    public sealed class FakePartyActorFeatureDriver : ApplicationIdentityFeatureDriver
    {
        static readonly ConcurrentDictionary<string, int> _actors = new( StringComparer.OrdinalIgnoreCase );
        static int _nextId = 1000;

        public FakePartyActorFeatureDriver( ApplicationIdentityService s )
            : base( s, isAllowedByDefault: true )
        {
        }

        public static int IdOf( IParty p ) => _actors.GetOrAdd( p.FullName, _ => System.Threading.Interlocked.Increment( ref _nextId ) );

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( Register( context ) );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( Register( context ) );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;

        static bool Register( FeatureLifetimeContext context )
        {
            return ((System.Collections.Generic.IEnumerable<IParty>)context.GetAllLocals()).Concat( context.GetAllRemotes() )
                        .All( p => p.TrySetPartyActorId( context.Monitor, IdOf( p ) ) );
        }
    }

    static readonly Type[] _types = [typeof( CurrentLocalParty ),
                                     typeof( CurrentLocalPartyDefaultProvider ),
                                     typeof( AuthCenterFeatureDriver ),
                                     typeof( IGetPartyActorIdsQCommand ),
                                     typeof( IPartyActorIds ),
                                     typeof( RawCrisExecutor ),
                                     typeof( RawCrisReceiver ),
                                     typeof( CrisDirectory ),
                                     typeof( ICrisResultError )];

    // Not RunningApplication.Port (CK.AppIdentity.Cris.Tests may run concurrently) nor the one of the RelayTests.
    const int Port = 37146;

    static Task<RunningApplication> StartRemoteAsync()
    {
        // The remote's AuthCenter is its remote "$Listener".
        return RunningApplication.CreateAsync( TestHelper.Monitor, true, c =>
        {
            c["Local:AllowFeatures"] = "AuthCenterRemote";
            c["Parties:0:AllowFeatures"] = "AuthCenter";
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{Port}";
        }, null, [.. _types, typeof( RemoteAuthCenterFeatureDriver )] );
    }

    static Task<RunningApplication> StartAuthCenterAsync( bool withRegistrar = true )
    {
        Type[] types = [.. _types, typeof( LocalAuthCenterFeatureDriver ), typeof( AuthCenterPartyActorIdsHandler )];
        return RunningApplication.CreateAsync( TestHelper.Monitor, false, c =>
        {
            c["Defaults:AllowFeatures"] = "AuthCenter,AuthCenterRemote";
            c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{Port}";
        }, null, withRegistrar ? [.. types, typeof( FakePartyActorFeatureDriver )] : types );
    }

    static RemoteAuthCenter RemoteCenter( RunningApplication remote ) => remote.ApplicationIdentityService.GetRequiredFeature<RemoteAuthCenter>();

    [Test]
    public async Task a_remote_gets_its_ids_from_its_AuthCenter_Async()
    {
        await using var center = await StartAuthCenterAsync();
        await using var remote = await StartRemoteAsync();
        var r = RemoteCenter( remote );
        (await r.PartyActorIdsResolution.WaitAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();

        var centerSide = center.ApplicationIdentityService;
        var remoteSide = remote.ApplicationIdentityService;
        // The remote's own id is the one of the AuthCenter's remote for it.
        remoteSide.PartyActorId.ShouldBe( centerSide.Remotes.Single().PartyActorId );
        remoteSide.PartyActorId.ShouldBe( FakePartyActorFeatureDriver.IdOf( remoteSide ) );
        // The AuthCenter's id, as seen by the remote.
        ((IRemoteParty)r.Center.AuthCenter).PartyActorId.ShouldBe( centerSide.PartyActorId );
        centerSide.PartyActorId.ShouldBeGreaterThan( 0 );
    }

    [Test]
    public async Task while_the_AuthCenter_is_unreachable_the_ids_are_0_Async()
    {
        RunningApplication? center = null;
        await using var remote = await StartRemoteAsync();
        try
        {
            var r = RemoteCenter( remote );
            await Task.Delay( 200 );
            r.PartyActorIdsResolution.IsCompleted.ShouldBeFalse();
            remote.ApplicationIdentityService.PartyActorId.ShouldBe( 0 );
            ((IRemoteParty)r.Center.AuthCenter).PartyActorId.ShouldBe( 0 );

            // The query is sent as soon as the AuthCenter is reachable.
            center = await StartAuthCenterAsync();
            (await r.PartyActorIdsResolution.WaitAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();
            remote.ApplicationIdentityService.PartyActorId.ShouldBeGreaterThan( 0 );
        }
        finally
        {
            if( center != null ) await center.DisposeAsync();
        }
    }

    [Test]
    public async Task an_AuthCenter_without_registrar_leaves_the_ids_to_0_Async()
    {
        await using var center = await StartAuthCenterAsync( withRegistrar: false );
        await using var remote = await StartRemoteAsync();
        var r = RemoteCenter( remote );
        (await r.PartyActorIdsResolution.WaitAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeFalse();
        remote.ApplicationIdentityService.PartyActorId.ShouldBe( 0 );
        ((IRemoteParty)r.Center.AuthCenter).PartyActorId.ShouldBe( 0 );
    }
}
