using CK.Core;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using NUnit.Framework;
using System;
using System.Collections.Generic;
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
            var c = TestHelper.CreateAppIdentityConfiguration( c =>
            {
                c["EnvironmentName"] = "Production";
                c["Local:Name"] = "MyApp";
                c["Remotes:0:Name"] = "Remote1";
                c["Remotes:1:Name"] = "Remote2";
            } );
            ServiceCollection serviceBuilder = new ServiceCollection();
            serviceBuilder.AddSingleton( c );
            serviceBuilder.AddSingleton<AppIdentityService>();
            var services = serviceBuilder.BuildServiceProvider();

            var s = services.GetRequiredService<AppIdentityService>();
            // This is done by host. We wait for the FeatureBuildersInitialization task.
            _ = ((IHostedService)s).StartAsync( default );

            await s.FeatureBuildersInitialization;
            s.DomainName.Should().Be( "LocalDev" );
            s.EnvironmentName.Should().Be( "Production" );
            s.Local.Name.Should().Be( "MyApp" );
            s.Local.Features.Should().BeEmpty();

            s.Remotes.Should().HaveCount( 2 );
            var r1 = s.Remotes.Single( r => r.Name == "Remote1" );
            r1.IsDynamic.Should().BeFalse();
            r1.Uri.Should().BeNull();
            r1.DomainName.Should().Be( "LocalDev" );
            r1.EnvironmentName.Should().Be( "Production" );
            r1.Features.Should().BeEmpty();

            var r2 = s.Remotes.Single( r => r.Name == "Remote2" );
            r2.IsDynamic.Should().BeFalse();
            r2.Uri.Should().BeNull();
            r2.DomainName.Should().Be( "LocalDev" );
            r2.EnvironmentName.Should().Be( "Production" );
            r2.Features.Should().BeEmpty();

        }

        [CKTypeDefiner]
        public abstract class CheckOrderFeatureBuilder : AppIdentityFeatureBuilder
        {
            static int _current;

            public static void Reset() => _current = 0;

            protected CheckOrderFeatureBuilder( AppIdentityService s )
                : base( s )
            {
            }

            public int OrderInitialization { get; private set; }

            protected override Task InitializeAsync( IActivityMonitor monitor, AppIdentityAgent appIdentityAgent )
            {
                OrderInitialization = _current++;
                monitor.Trace( $"Initialized {GetType().Name} ({OrderInitialization})." );
                return Task.CompletedTask;
            }
        }

        public class F1 : CheckOrderFeatureBuilder
        {
            public F1( AppIdentityService s ) : base( s )
            {
            }
        }

        public class F2_1 : CheckOrderFeatureBuilder
        {
            public F2_1( AppIdentityService s, F1 s1 ) : base( s )
            {
            }
        }

        public class F3_2 : CheckOrderFeatureBuilder
        {
            public F3_2( AppIdentityService s, F2_1 s2 ) : base( s )
            {
            }
        }

        public class FA_1 : CheckOrderFeatureBuilder
        {
            public FA_1( AppIdentityService s, F1 s1 ) : base( s )
            {
            }
        }

        public class FB_A : CheckOrderFeatureBuilder
        {
            public FB_A( AppIdentityService s, FA_1 sa ) : base( s )
            {
            }
        }

        public class FC_A_3 : CheckOrderFeatureBuilder
        {
            public FC_A_3( AppIdentityService s, FA_1 sa, F3_2 f1 ) : base( s )
            {
            }
        }

        public class FD_B_2 : CheckOrderFeatureBuilder
        {
            public FD_B_2( AppIdentityService s, FB_A sb, F2_1 f2 ) : base( s )
            {
            }
        }

        [TestCase( true )]
        [TestCase( false )]
        public async Task feature_builders_initialization_follows_the_dependency_order_Async( bool revert )
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( without_feature_builders_Async ) );
            CheckOrderFeatureBuilder.Reset();
            var c = TestHelper.CreateAppIdentityConfiguration();
            ServiceCollection serviceBuilder = new ServiceCollection();
            serviceBuilder.AddSingleton( c );
            serviceBuilder.AddSingleton<AppIdentityService>();
            var builderTypes = new List<Type>() { typeof( F1 ),
                                                  typeof( F2_1 ),
                                                  typeof( F3_2 ),
                                                  typeof( FA_1 ),
                                                  typeof( FB_A ),
                                                  typeof( FC_A_3 ),
                                                  typeof( FD_B_2 ) };
            if( revert ) builderTypes.Reverse();
            foreach( var t in builderTypes )
            {
                serviceBuilder.AddSingleton( t );
                serviceBuilder.AddSingleton( sp => (AppIdentityFeatureBuilder)sp.GetRequiredService( t ) );
            }
            var services = serviceBuilder.BuildServiceProvider();

            var s = services.GetRequiredService<AppIdentityService>();
            _ = ((IHostedService)s).StartAsync( default );
            await s.FeatureBuildersInitialization;

            var f1 = services.GetRequiredService<F1>();
            var f2_1 = services.GetRequiredService<F2_1>();
            var f3_2 = services.GetRequiredService<F3_2>();
            var fA_1 = services.GetRequiredService<FA_1>();
            var fB_A = services.GetRequiredService<FB_A>();
            var fC_A_3 = services.GetRequiredService<FC_A_3>();
            var fD_B_2 = services.GetRequiredService<FD_B_2>();
            f1.OrderInitialization.Should().Be( 0 );
            f2_1.OrderInitialization.Should().BeGreaterThan( f1.OrderInitialization );
            f3_2.OrderInitialization.Should().BeGreaterThan( f2_1.OrderInitialization );
            fA_1.OrderInitialization.Should().BeGreaterThan( f1.OrderInitialization );
            fB_A.OrderInitialization.Should().BeGreaterThan( fA_1.OrderInitialization );
            fC_A_3.OrderInitialization.Should().BeGreaterThan( fA_1.OrderInitialization ).And.BeGreaterThan( f3_2.OrderInitialization );
            fD_B_2.OrderInitialization.Should().BeGreaterThan( fB_A.OrderInitialization ).And.BeGreaterThan( f2_1.OrderInitialization );
        }
    }
}
