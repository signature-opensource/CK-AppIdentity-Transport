using CK.Core;
using CK.Cris;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The <see cref="ICrisCallEnvelope"/> of a dispatched command (<see cref="ICrisCallEnvelopeContributor"/>) and the
/// <see cref="ICrisChannelReceptionHandler"/> that configures the ambient services of a received command.
/// </summary>
public class ReceptionTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 30 );

    public interface ITestEnvelope : ICrisCallEnvelope
    {
        string? CultureName { get; set; }
    }

    // Answers the culture and the current local party of its execution.
    public interface IWhereCommand : ICommand<string>
    {
    }

    public interface IRefusedCommand : ICommand<string>
    {
    }

    // Executed in the channel scope: it answers its caller.
    public interface IWhoCalledCommand : ICommand<string>, ICommandEndpointOnly
    {
    }

    public sealed class ListenerSide : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IWhereCommand c, ExtendedCultureInfo culture, CurrentLocalParty party ) => $"{culture.Name}@{party.LocalParty.FullName}";

        [CommandHandler]
        public string Handle( IRefusedCommand c ) => "executed";

        [CommandHandler]
        public string Handle( IWhoCalledCommand c, IRemoteParty caller ) => caller.FullName;
    }

    // On the sender: the culture to use travels in the envelope.
    public sealed class TestContributor : ICrisCallEnvelopeContributor
    {
        public void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, ICrisCallEnvelope envelope )
        {
            if( command is IWhereCommand ) ((ITestEnvelope)envelope).CultureName = "fr";
        }
    }

    // On the listener: the culture of the envelope, or a refusal.
    public sealed class TestReceptionHandler : ICrisChannelReceptionHandler
    {
        public ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureAsync( IActivityMonitor monitor,
                                                                                           IServiceProvider services,
                                                                                           IRemoteParty caller,
                                                                                           IAbstractCommand command,
                                                                                           ICrisCallEnvelope envelope )
        {
            if( command is IRefusedCommand )
            {
                var e = services.GetRequiredService<PocoDirectory>().Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, "Refused at reception.", "Test.Refused" ) ) );
                return ValueTask.FromResult<(ICrisResultError?, AmbientServiceHub?)>( (e, null) );
            }
            var hub = services.GetRequiredService<AmbientServiceHub>().CleanClone();
            if( envelope is ITestEnvelope { CultureName: { } name } )
            {
                hub.Override<ExtendedCultureInfo>( NormalizedCultureInfo.EnsureNormalizedCultureInfo( name ) );
            }
            return ValueTask.FromResult<(ICrisResultError?, AmbientServiceHub?)>( (null, hub) );
        }
    }

    static readonly Type[] _common = [typeof( IWhereCommand ),
                                      typeof( IRefusedCommand ),
                                      typeof( IWhoCalledCommand ),
                                      typeof( ITestEnvelope ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver )];

    static IExecutingCommand Submit( RunningApplication app, IAbstractCommand command )
    {
        using var scope = app.CreateScopeServices();
        var hub = scope.ServiceProvider.GetRequiredService<AmbientServiceHub>().CleanClone();
        hub.Override<ExtendedCultureInfo>( NormalizedCultureInfo.EnsureNormalizedCultureInfo( "en" ) );
        return app.Services.GetRequiredService<CrisBackgroundExecutorService>().Submit( TestHelper.Monitor, command, hub );
    }

    [Test]
    public async Task the_reception_handler_configures_the_received_commands_from_their_envelope_Async()
    {
        NormalizedCultureInfo.EnsureNormalizedCultureInfo( "fr" );
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null, [.. _common, typeof( TestContributor )] );
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null, [.. _common, typeof( ListenerSide ), typeof( TestReceptionHandler )] );

        // Dispatched in an envelope: the listener executes it with the culture it carries, for the owner of the remote.
        var where = await Submit( sender, sender.PocoDirectory.Create<IWhereCommand>() ).ExecutedCommand.WaitAsync( _timeout );
        where.Result.ShouldBe( $"fr@{listener.ApplicationIdentityService.FullName}" );

        // Refused at reception.
        var refused = await Submit( sender, sender.PocoDirectory.Create<IRefusedCommand>() ).ExecutedCommand.WaitAsync( _timeout );
        refused.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().ResName.ShouldBe( "Test.Refused" );

        // An endpoint-only command is not configured: it executes in the channel scope, with its caller.
        var who = await sender.CrisChannel.SendCommand( TestHelper.Monitor, sender.PocoDirectory.Create<IWhoCalledCommand>() ).ExecutedCommand.WaitAsync( _timeout );
        who.Result.ShouldBe( sender.ApplicationIdentityService.FullName.Path );
    }
}
