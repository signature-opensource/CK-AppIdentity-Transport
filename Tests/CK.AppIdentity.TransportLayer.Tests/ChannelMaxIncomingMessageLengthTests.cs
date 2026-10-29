using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// A channel declares the <see cref="MessageProtocol.MaxIncomingMessageLength"/> of its protocols.
/// </summary>
[TestFixture]
public class ChannelMaxIncomingMessageLengthTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    async Task<ApplicationIdentityService> CreateAsync( int maxIncomingMessageLength, CancellationToken token )
    {
        // No listener: the channel exists but is not connected.
        return await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$MaxLength";
            c["Defaults:AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = "Other";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37199";
        }, services =>
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
            services.AddSingleton( sp => new CountingChannelFeatureDriver( sp.GetRequiredService<TransportFeatureDriver>() )
            {
                MaxIncomingMessageLength = maxIncomingMessageLength
            } );
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<CountingChannelFeatureDriver>() );
        }, token: token );
    }

    [TestCase( 0, MessageProtocol.DefaultMaxIncomingMessageLength )]
    [TestCase( 64 * 1024 * 1024, 64 * 1024 * 1024 )]
    [CancelAfter( 30000 )]
    public async Task the_channel_protocol_has_the_channel_MaxIncomingMessageLength_Async( int declared, int expected, CancellationToken token )
    {
        await using var app = await CreateAsync( declared, token );
        var channel = app.AllRemotes.Single().GetRequiredFeature<CountingChannelFeature>();
        channel.SupportedProtocols.Single().MaxIncomingMessageLength.ShouldBe( expected );
    }

    [Test]
    public void a_protocol_cannot_be_registered_with_another_MaxIncomingMessageLength()
    {
        var dir = new MessageProtocolDirectoryService();
        dir.TryRegister( TestHelper.Monitor, "Test", 0, out var p1 ).ShouldBeTrue();
        // The default is the same as the explicit default.
        dir.TryRegister( TestHelper.Monitor, "Test", 0, out var p2, MessageProtocol.DefaultMaxIncomingMessageLength ).ShouldBeTrue();
        p2.ShouldBeSameAs( p1 );

        dir.TryRegister( TestHelper.Monitor, "Test", 0, out var p3, 1024 ).ShouldBeFalse();
        p3.ShouldBeNull();
    }
}
