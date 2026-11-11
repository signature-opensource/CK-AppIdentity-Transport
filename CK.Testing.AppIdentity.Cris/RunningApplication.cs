using CK.AppIdentity;
using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.Setup;
using CK.Testing;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.Testing.AppIdentity.Cris;

/// <summary>
/// Encapsulates what is required to create a Cris application that talks to another one.
/// </summary>
public sealed class RunningApplication : IAsyncDisposable
{
    /// <summary>
    /// The TCP port the "Test/$Listener" listens on and the "Test/$Sender" connects to.
    /// </summary>
    public const int Port = 37140;

    static int _creationCount;

    readonly AutomaticServices _s;
    readonly PocoDirectory _pocoDirectory;
    readonly ApplicationIdentityService _appIdentityService;
    readonly TransportManagerFeature _transport;
    readonly CrisChannelFeature? _channel;
    readonly bool _isSender;

    /// <summary>
    /// Gets the Poco directory.
    /// </summary>
    public PocoDirectory PocoDirectory => _pocoDirectory;

    /// <summary>
    /// Gets the root application identity service. It is started and its <see cref="ApplicationIdentityService.InitializationTask"/>
    /// has completed. It must not be disposed: calling this <see cref="DisposeAsync()"/> stops and dispose
    /// everything.
    /// </summary>
    public ApplicationIdentityService ApplicationIdentityService => _appIdentityService;

    /// <summary>
    /// Gets whether this application has been initialized as the "Test/$Sender".
    /// </summary>
    public bool IsSender => _isSender;

    /// <summary>
    /// Gets the transport feature.
    /// </summary>
    public TransportManagerFeature Transport => _transport;

    /// <summary>
    /// Gets the Cris channel.
    /// </summary>
    public CrisChannelFeature CrisChannel => _channel ?? throw new InvalidOperationException( "This application has no \"$Listener\" or \"$Sender\" remote (its configuration renamed it)." );

    /// <summary>
    /// Gets the global, root, service provider: <see cref="CreateScopeServices"/> or <see cref="CreateAsyncScopeServices"/>
    /// should be used to obtain a short lived <see cref="IServiceScope"/> (otherwise scoped services
    /// will be resolved in this root service provider).
    /// </summary>
    public IServiceProvider Services => _s.Services;

    /// <summary>
    /// Creates a disposable scoped provider.
    /// </summary>
    /// <returns>The scoped services.</returns>
    public IServiceScope CreateScopeServices() => _s.Services.CreateScope();

    /// <summary>
    /// Creates an async disposable scoped provider.
    /// </summary>
    /// <returns>The scoped services.</returns>
    public AsyncServiceScope CreateAsyncScopeServices() => _s.Services.CreateAsyncScope();

    /// <summary>
    /// Dispose the root service provider.
    /// </summary>
    /// <returns>The awaitable.</returns>
    public ValueTask DisposeAsync() => _s.DisposeAsync();

    RunningApplication( AutomaticServices s, bool isSender )
    {
        _s = s;
        _isSender = isSender;
        _appIdentityService = s.Services.GetRequiredService<ApplicationIdentityService>();
        _transport = _appIdentityService.GetRequiredFeature<TransportManagerFeature>();
        _pocoDirectory = s.Services.GetRequiredService<PocoDirectory>();
        // A configuration may rename the remote (a chain of applications): the channel is then not available.
        _channel = _appIdentityService.Remotes.FirstOrDefault( r => r.PartyName == (isSender ? "$Listener" : "$Sender") )?.GetRequiredFeature<CrisChannelFeature>();
    }

    /// <summary>
    /// Creates a running sender or listener application.
    /// </summary>
    /// <param name="isSender">
    /// True to create a "Test/$Sender" application that initiate connections to a "Test/$Listener" remote.
    /// False for the opposite.
    /// </param>
    /// <param name="configuration">
    /// Optional configurator for the <see cref="MutableConfigurationSection"/>.
    /// Used by <see cref="ApplicationIdentityServiceConfiguration.Create(IActivityMonitor, Action{MutableConfigurationSection})"/>.
    /// This is called after the $Sender/$Listener configuration: anything can be changed.
    /// </param>
    /// <param name="configureServices">
    /// Optional services configuration. Calls after the default services initialization: services can be overridden as needed.
    /// </param>
    /// <param name="types">
    /// Types to register. Fills the <see cref="BinPathConfiguration.Types"/>.
    /// </param>
    /// <returns>A running application.</returns>
    public static async Task<RunningApplication> CreateAsync( IActivityMonitor monitor,
                                                              bool isSender,
                                                              Action<MutableConfigurationSection>? configuration,
                                                              Action<IServiceCollection>? configureServices,
                                                              params Type[] types )
    {
        var engineConfiguration = TestHelper.CreateDefaultEngineConfiguration();
        // Each application has its own folder: the generated assembly of a previous application of this
        // process is loaded and cannot be cleaned up. This also gives each application a fresh key store.
        var outputPath = TestHelper.TestProjectFolder.Combine( $"$StObjGen/{(isSender ? "Sender" : "Listener")}/{Interlocked.Increment( ref _creationCount )}" );
        TestHelper.CleanupFolder( outputPath );
        engineConfiguration.FirstBinPath.OutputPath = outputPath;
        engineConfiguration.FirstBinPath.GenerateSourceFiles = false;

        engineConfiguration.FirstBinPath.Types.Add( isSender ? typeof( SenderHandler ) : typeof( ListenerHandler ),
                                                    typeof( ISenderCommand ),
                                                    typeof( IListenerCommand ),
                                                    typeof( IListenerImmediateEvent ),
                                                    typeof( IWhoAmICommand ),
                                                    typeof( CrisExecutionHost ),
                                                    typeof( ApplicationIdentityService ),
                                                    typeof( PartyDescriptionFeatureDriver ),
                                                    typeof( MessageProtocolDirectoryService ),
                                                    typeof( TransportFeatureDriver ),
                                                    typeof( CrisChannelFeatureDriver ),
                                                    typeof( AppIdentityDIContainerDefinition ),
                                                    typeof( AuthenticationInfoDefaultProvider ),
                                                    typeof( KeyManagementFeatureDriver ),
                                                    typeof( DefaultCoreKeyStore ),
                                                    typeof( TcpSocketTransportTypeService ) );
        engineConfiguration.FirstBinPath.Types.Add( types );

        EngineResult r = await engineConfiguration.RunSuccessfullyAsync();
        AutomaticServices services = r.CreateAutomaticServices( configureServices: services =>
        {
            var appIdentityConfiguration = ApplicationIdentityServiceConfiguration.Create( monitor, c =>
            {
                c["StoreRootPath"] = outputPath.AppendPart( "AppStore" );
                c["FullName"] = (isSender ? "Test/$Sender" : "Test/$Listener");
                c["Parties:0:PartyName"] = isSender ? "$Listener" : "$Sender";
                // Both applications have a fresh key store: they trust each other on first contact.
                c["Parties:0:AutoTrustKey"] = "Once";
                // A dedicated port: the default 37120 one is used by other test assemblies that
                // can run concurrently.
                if( isSender )
                {
                    c["Parties:0:Address"] = $"tcp:127.0.0.1:{Port}";
                }
                else
                {
                    c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{Port}";
                }
                configuration?.Invoke( c );
            } );
            services.AddSingleton( appIdentityConfiguration.ShouldNotBeNull() );
            services.AddSingleton( SystemClockTester.NoHeartBeat );
            services.AddSingleton<IDataProtectionProvider>( FakeProtector.Fake );
            configureServices?.Invoke( services );
        } );
        // Features (TransportManagerFeature, the remotes' CrisChannelFeature) only exist once the
        // service has been started and its initialization is done.
        var appIdentityService = services.Services.GetRequiredService<ApplicationIdentityService>();
        _ = ((IHostedService)appIdentityService).StartAsync( default );
        await appIdentityService.InitializationTask.ConfigureAwait( false );
        return new RunningApplication( services, isSender );
    }

    /// <summary>
    /// Creates a running "Test/$Listener" and then a running "Test/$Sender" that connects to it.
    /// <para>
    /// The listener is started first, so the sender's first connection attempt succeeds. The applications have no heart beat
    /// (<see cref="SystemClockTester.NoHeartBeat"/>): a failed connection attempt is never retried. A sender started before its
    /// listener races with it (the attempt fails if the listener isn't listening yet) and may never connect. A test that needs
    /// the sender first (what happens before the remote exists) gives the sender a heart beat: <see cref="WithHeartBeat"/>.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="senderConfiguration">Optional configurator of the sender (see <see cref="CreateAsync"/>).</param>
    /// <param name="senderTypes">Types of the sender.</param>
    /// <param name="listenerConfiguration">Optional configurator of the listener (see <see cref="CreateAsync"/>).</param>
    /// <param name="listenerTypes">Types of the listener.</param>
    /// <param name="senderServices">Optional services configuration of the sender.</param>
    /// <param name="listenerServices">Optional services configuration of the listener.</param>
    /// <returns>The running pair.</returns>
    public static async Task<RunningApplicationPair> CreatePairAsync( IActivityMonitor monitor,
                                                                      Action<MutableConfigurationSection>? senderConfiguration = null,
                                                                      Type[]? senderTypes = null,
                                                                      Action<MutableConfigurationSection>? listenerConfiguration = null,
                                                                      Type[]? listenerTypes = null,
                                                                      Action<IServiceCollection>? senderServices = null,
                                                                      Action<IServiceCollection>? listenerServices = null )
    {
        var listener = await CreateAsync( monitor, false, listenerConfiguration, listenerServices, listenerTypes ?? [] ).ConfigureAwait( false );
        try
        {
            var sender = await CreateAsync( monitor, true, senderConfiguration, senderServices, senderTypes ?? [] ).ConfigureAwait( false );
            return new RunningApplicationPair( sender, listener );
        }
        catch
        {
            await listener.DisposeAsync().ConfigureAwait( false );
            throw;
        }
    }

    /// <summary>
    /// Gives an application a heart beat (a 100 ms period): its failed connection attempts are retried. This is required by
    /// a sender that is started before its listener (see <see cref="CreatePairAsync"/>).
    /// </summary>
    /// <param name="configureServices">Optional other services configuration.</param>
    /// <returns>The services configuration to give to <see cref="CreateAsync"/>.</returns>
    public static Action<IServiceCollection> WithHeartBeat( Action<IServiceCollection>? configureServices = null )
    {
        return services =>
        {
            configureServices?.Invoke( services );
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( new SystemClockTester( 100 ) );
        };
    }

}
