using CK.AppIdentity.TransportLayer;
using CK.AppIdentity.TransportLayer.Testing;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;


/// <summary>
/// Helper that can start 2 <see cref="ApplicationIdentityService"/>: one with a listener and the other one with a sender
/// bound to each other so they can send/receive bytes from each other.
/// </summary>
public sealed class CrisChannelTester : IAsyncDisposable
{
    readonly ApplicationIdentityService _sender;
    readonly ApplicationIdentityService _listener;
    readonly TransportManagerFeature _senderTransport;
    readonly TransportManagerFeature _listenerTransport;
    readonly CrisChannelFeature _senderChannel;
    readonly CrisChannelFeature _listenerChannel;

    public TransportManagerFeature SenderTransport => _senderTransport;

    public CrisChannelFeature SenderChannel => _senderChannel;

    public TransportManagerFeature ListenerTransport => _listenerTransport;

    public CrisChannelFeature ListenerChannel => _listenerChannel;

    /// <summary>
    /// Dispose the sender and listener.
    /// </summary>
    /// <returns></returns>
    public async ValueTask DisposeAsync()
    {
        await _sender.DisposeAsync();
        await _listener.DisposeAsync();
    }

    /// <summary>
    /// Initializes a new tester bound to 2 sides that must be correctly configured with a
    /// remote named "$Listener" (for the sender) and a remote named "$Sender" (for the receiver) bound
    /// to each other.
    /// Note that disposing the tester will dispose both sides.
    /// </summary>
    /// <param name="sender">The "sender" side (can be any of the two).</param>
    /// <param name="listener">The "listener" side (the other one).</param>
    public CrisChannelTester( ApplicationIdentityService sender, ApplicationIdentityService listener )
    {
        _sender = sender;
        _listener = listener;
        _senderTransport = sender.GetRequiredFeature<TransportManagerFeature>();
        _listenerTransport = listener.GetRequiredFeature<TransportManagerFeature>();
        _senderChannel = sender.Remotes.First( r => r.PartyName == "$Listener" ).GetRequiredFeature<CrisChannelFeature>();
        _listenerChannel = listener.Remotes.First( r => r.PartyName == "$Sender" ).GetRequiredFeature<CrisChannelFeature>();
    }

    /// <summary>
    /// Uses <see cref="CreateAndStartListenerAsync(string, NormalizedPath, Action{ServiceCollection}?, CancellationToken)"/>
    /// and <see cref="CreateAndStartSenderAsync(string, NormalizedPath, Action{ServiceCollection}?, CancellationToken)"/>
    /// to create a <see cref="CrisChannelTester"/> on the two <see cref="ApplicationIdentityService"/>.
    /// </summary>
    /// <param name="autoTrustKey">The AutoTrustKey configuration to use (same on both side).</param>
    /// <param name="heartbeatPeriod">The <see cref="ApplicationIdentityService.ISystemClock.HeatBeatPeriod"/> to use (same on both side).</param>
    /// <param name="storeSubPath">Optional file store sub path.</param>
    /// <returns>A running <see cref="CrisChannelTester"/>.</returns>
    public static async Task<CrisChannelTester> CreateTesterAsync( string autoTrustKey = "Never",
                                                                   int heartbeatPeriod = 0,
                                                                   NormalizedPath storeSubPath = default )
    {
        var clock = new SystemClockTester( heartbeatPeriod );
        var s = await CreateAndStartSenderAsync( autoTrustKey, storeSubPath, null, services => services.AddSingleton( clock ) );
        var l = await CreateAndStartListenerAsync( autoTrustKey, storeSubPath, null, services => services.AddSingleton( clock ) );

        return new CrisChannelTester( s, l );
    }

    /// <summary>
    /// Creates a "Test/$Sender" <see cref="ApplicationIdentityService"/> with a remote party "Test/$Listener"
    /// that targets the Address = "tcp:127.0.0.1". This will use the default 37120 port.
    /// The "Cris" feature is not specified because it is opt-out.
    /// </summary>
    /// <param name="autoTrustKey">The AutoTrustKey configuration to use.</param>
    /// <param name="storeSubPath">Optional file store sub path.</param>
    /// <param name="configureServices">Optional services configurator.</param>
    /// <param name="token">Optional cancellation token.</param>
    /// <returns></returns>
    public static async Task<ApplicationIdentityService> CreateAndStartSenderAsync( string autoTrustKey = "Never",
                                                                                    NormalizedPath storeSubPath = default,
                                                                                    Action<MutableConfigurationSection>? configuration = null,
                                                                                    Action<ServiceCollection>? configureServices = null,
                                                                                    CancellationToken token = default )
    {
        return await TestHelper.CreateApplicationServiceAsync( c =>
        {
            if( !storeSubPath.IsEmptyPath ) c["RootStorePath"] = TestHelper.TestProjectFolder.Combine( storeSubPath );
            c["AutoTrustKey"] = autoTrustKey;
            c["FullName"] = "Test/$Sender";
            c["Parties:0:PartyName"] = "$Listener";
            c["Parties:0:Address"] = "tcp:127.0.0.1";
            configuration?.Invoke( c );
        }, Configure( configureServices ), token );
    }

    /// <summary>
    /// Creates a "Test/$Listener" <see cref="ApplicationIdentityService"/> with a remote party "Test/$Sender".
    /// This uses the default configuration: the TCP listener will listen to "127.0.0.1:37120".
    /// The "Cris" feature is not specified because it is opt-out.
    /// </summary>
    /// <param name="autoTrustKey">The AutoTrustKey configuration to use.</param>
    /// <param name="storeSubPath">Optional file store sub path.</param>
    /// <param name="configureServices">Optional services configurator.</param>
    /// <param name="token">Optional cancellation token.</param>
    /// <returns></returns>
    public static async Task<ApplicationIdentityService> CreateAndStartListenerAsync( string autoTrustKey = "Never",
                                                                                      NormalizedPath storeSubPath = default,
                                                                                      Action<MutableConfigurationSection>? configuration = null,
                                                                                      Action<ServiceCollection>? configureServices = null,
                                                                                      CancellationToken token = default )
    {
        return await TestHelper.CreateApplicationServiceAsync( c =>
        {
            if( !storeSubPath.IsEmptyPath ) c["RootStorePath"] = TestHelper.TestProjectFolder.Combine( storeSubPath );
            c["AutoTrustKey"] = autoTrustKey;
            c["FullName"] = "Test/$Listener";
            c["Parties:0:PartyName"] = "$Sender";
            configuration?.Invoke( c );
        }, Configure( configureServices ), token );
    }

    static Action<ServiceCollection> Configure( Action<ServiceCollection>? configureServices )
    {
        return services =>
        {
            services.AddSingleton<CrisChannelFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<BlobChannelFeatureDriver>() );
            configureServices?.Invoke( services );
        };
    }

}
