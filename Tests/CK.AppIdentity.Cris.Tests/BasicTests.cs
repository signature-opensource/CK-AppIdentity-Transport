using CK.Core;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

public class BasicTests
{
    [Test]
    public async Task basic_sending_and_receiving_Async()
    {
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null );
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null );

        // Checks that Listener/Sender are actually different thanks to the handlers.
        sender.Services.GetService<SenderHandler>().ShouldNotBeNull();
        sender.Services.GetService<ListenerHandler>().ShouldBeNull();

        listener.Services.GetService<SenderHandler>().ShouldBeNull();
        listener.Services.GetService<ListenerHandler>().ShouldNotBeNull();

        var sC = sender.PocoDirectory.Create<ISenderCommand>( c => c.Message = "Hello" );
        sender.CrisChannel.SendCommand( TestHelper.Monitor, sC );
    }

}
