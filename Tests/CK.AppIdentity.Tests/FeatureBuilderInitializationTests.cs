using CK.Core;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Tests
{

    [TestFixture]
    public class FeatureBuilderInitializationTests
    {
        [Test]
        public async Task without_feature_builders_Async()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( without_feature_builders_Async ) );
            await using ApplicationIdentityService s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["EnvironmentName"] = "Production";
                c["Local:Name"] = "MyApp";
                c["Remotes:0:Name"] = "Remote1";
                c["Remotes:1:Name"] = "Remote2";
            } );

            s.DomainName.Should().Be( "Default" );
            s.EnvironmentName.Should().Be( "Production" );
            s.Local.Name.Should().Be( "MyApp" );
            s.Local.Features.Should().BeEmpty();

            s.Remotes.Should().HaveCount( 2 );
            var r1 = s.Remotes.Single( r => r.Name == "Remote1" );
            r1.IsDynamic.Should().BeFalse();
            r1.Address.Should().BeNull();
            r1.DomainName.Should().Be( "Default" );
            r1.EnvironmentName.Should().Be( "Production" );
            r1.Features.Should().BeEmpty();

            var r2 = s.Remotes.Single( r => r.Name == "Remote2" );
            r2.IsDynamic.Should().BeFalse();
            r2.Address.Should().BeNull();
            r2.DomainName.Should().Be( "Default" );
            r2.EnvironmentName.Should().Be( "Production" );
            r2.Features.Should().BeEmpty();

        }

        [CKTypeDefiner]
        public abstract class CheckOrderFeatureDriver : ApplicationIdentityFeatureDriver
        {
            internal static int _count;
            internal static int _currentSetupOrder;
            internal static int _setupDynamicCount;
            internal static int _teardownDynamicCount;
            internal static int _teardownCount;

            public static void Reset()
            {
                _count = 0;
                _currentSetupOrder = 0;
                _setupDynamicCount = 0;
                _teardownDynamicCount = 0;
                _teardownCount = 0;
            }

            protected CheckOrderFeatureDriver( ApplicationIdentityService s )
                : base( s, true )
            {
                ++_count;
            }

            public int SetupOrder { get; private set; }

            protected override Task<bool> SetupAsync(FeatureLifetimeContext context)
            {
                SetupOrder = _currentSetupOrder++;
                context.Monitor.Trace( $"Setup {GetType().Name} ({SetupOrder})." );
                return Task.FromResult( true );
            }

            protected override Task<bool> SetupDynamicRemoteAsync(FeatureLifetimeContext context, IRemoteParty remoteParty)
            {
                _setupDynamicCount++;
                context.Memory.GetValueOrDefault( "SetupDynamicOrder", 0 ).Should().Be( SetupOrder );
                context.Memory["SetupDynamicOrder"] = SetupOrder + 1;
                return Task.FromResult( true );
            }

            protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty party )
            {
                _teardownDynamicCount++;
                context.Memory.GetValueOrDefault( "TeardownDynamicOrder", _currentSetupOrder ).Should().Be( _currentSetupOrder - SetupOrder );
                context.Memory["TeardownDynamicOrder"] = _currentSetupOrder - SetupOrder - 1;
                return Task.CompletedTask;
            }

            protected override Task TeardownAsync( FeatureLifetimeContext context )
            {
                _teardownCount++;
                context.Memory.GetValueOrDefault( "TeardownOrder", _currentSetupOrder ).Should().Be( _currentSetupOrder - SetupOrder );
                context.Memory["TeardownOrder"] = _currentSetupOrder - SetupOrder - 1;
                return Task.CompletedTask;
            }
        }

        public class F1FeatureDriver : CheckOrderFeatureDriver
        {
            public F1FeatureDriver( ApplicationIdentityService s ) : base( s )
            {
            }
        }

        public class F2_1FeatureDriver : CheckOrderFeatureDriver
        {
            public F2_1FeatureDriver( ApplicationIdentityService s, F1FeatureDriver s1 ) : base( s )
            {
            }
        }

        public class F3_2FeatureDriver : CheckOrderFeatureDriver
        {
            public F3_2FeatureDriver( ApplicationIdentityService s, F2_1FeatureDriver s2 ) : base( s )
            {
            }
        }

        public class FA_1FeatureDriver : CheckOrderFeatureDriver
        {
            public FA_1FeatureDriver( ApplicationIdentityService s, F1FeatureDriver s1 ) : base( s )
            {
            }
        }

        public class FB_AFeatureDriver : CheckOrderFeatureDriver
        {
            public FB_AFeatureDriver( ApplicationIdentityService s, FA_1FeatureDriver sa ) : base( s )
            {
            }
        }

        public class FC_A_3FeatureDriver : CheckOrderFeatureDriver
        {
            public FC_A_3FeatureDriver( ApplicationIdentityService s, FA_1FeatureDriver sa, F3_2FeatureDriver f1 ) : base( s )
            {
            }
        }

        public class FD_B_2FeatureDriver : CheckOrderFeatureDriver
        {
            public FD_B_2FeatureDriver( ApplicationIdentityService s, FB_AFeatureDriver sb, F2_1FeatureDriver f2 ) : base( s )
            {
            }
        }

        [TestCase( true )]
        [TestCase( false )]
        public async Task feature_builders_initialization_follows_the_dependency_order_Async( bool revert )
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( feature_builders_initialization_follows_the_dependency_order_Async ) );
            CheckOrderFeatureDriver.Reset();
            var c = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, c => c["Local:Name"] = "FakeApp" );
            Debug.Assert( c != null );
            ServiceCollection serviceBuilder = new ServiceCollection();
            serviceBuilder.AddSingleton( c );
            serviceBuilder.AddSingleton<ApplicationIdentityService>();
            var builderTypes = new List<Type>() { typeof( F1FeatureDriver ),
                                                  typeof( F2_1FeatureDriver ),
                                                  typeof( F3_2FeatureDriver ),
                                                  typeof( FA_1FeatureDriver ),
                                                  typeof( FB_AFeatureDriver ),
                                                  typeof( FC_A_3FeatureDriver ),
                                                  typeof( FD_B_2FeatureDriver ) };
            if( revert ) builderTypes.Reverse();
            foreach( var t in builderTypes )
            {
                serviceBuilder.AddSingleton( t );
                serviceBuilder.AddSingleton( sp => (ApplicationIdentityFeatureDriver)sp.GetRequiredService( t ) );
            }
            var services = serviceBuilder.BuildServiceProvider();

            var s = services.GetRequiredService<ApplicationIdentityService>();

            _ = ((IHostedService)s).StartAsync( default );
            await s.FeatureBuildersInitialization;

            var f1 = services.GetRequiredService<F1FeatureDriver>();
            var f2_1 = services.GetRequiredService<F2_1FeatureDriver>();
            var f3_2 = services.GetRequiredService<F3_2FeatureDriver>();
            var fA_1 = services.GetRequiredService<FA_1FeatureDriver>();
            var fB_A = services.GetRequiredService<FB_AFeatureDriver>();
            var fC_A_3 = services.GetRequiredService<FC_A_3FeatureDriver>();
            var fD_B_2 = services.GetRequiredService<FD_B_2FeatureDriver>();
            CheckOrderFeatureDriver._count.Should().Be( 7 );

            f1.FeatureName.Should().Be( "F1" );
            f2_1.FeatureName.Should().Be( "F2_1" );
            f3_2.FeatureName.Should().Be( "F3_2" );
            fA_1.FeatureName.Should().Be( "FA_1" );
            fB_A.FeatureName.Should().Be( "FB_A" );
            fC_A_3.FeatureName.Should().Be( "FC_A_3" );
            fD_B_2.FeatureName.Should().Be( "FD_B_2" );

            f1.SetupOrder.Should().Be( 0 );
            f2_1.SetupOrder.Should().BeGreaterThan( f1.SetupOrder );
            f3_2.SetupOrder.Should().BeGreaterThan( f2_1.SetupOrder );
            fA_1.SetupOrder.Should().BeGreaterThan( f1.SetupOrder );
            fB_A.SetupOrder.Should().BeGreaterThan( fA_1.SetupOrder );
            fC_A_3.SetupOrder.Should().BeGreaterThan( fA_1.SetupOrder ).And.BeGreaterThan( f3_2.SetupOrder );
            fD_B_2.SetupOrder.Should().BeGreaterThan( fB_A.SetupOrder ).And.BeGreaterThan( f2_1.SetupOrder );

            var r = await s.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["Name"] = "SomeDynamicRemote";
            } );
            Debug.Assert( r != null );
            CheckOrderFeatureDriver._setupDynamicCount.Should().Be( 7 );
            CheckOrderFeatureDriver._teardownDynamicCount.Should().Be( 0 );

            await r.DestroyAsync();
            CheckOrderFeatureDriver._teardownDynamicCount.Should().Be( 7 );
            CheckOrderFeatureDriver._teardownCount.Should().Be( 0 );

            await s.DisposeAsync();
            CheckOrderFeatureDriver._teardownCount.Should().Be( 7 );
        }
    }
}
