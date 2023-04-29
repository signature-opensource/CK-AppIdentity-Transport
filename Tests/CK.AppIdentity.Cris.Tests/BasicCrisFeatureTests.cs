using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using static CK.Testing.StObjEngineTestHelper;

namespace CK.AppIdentity.Cris.Tests
{

    [TestFixture]
    public class BasicCrisFeatureTests
    {
        public interface ISimpleCommand : ICommand
        {
            string Name { get; set; }
        }

        public interface ISimpleGet : ICommand<int>
        {
            string Name { get; set; }
        }

        [Test]
        public async Task simple_exchange_Async()
        {
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "Listener";
                c["Remotes:0:Name"] = "Sender";
                c["AllowFeatures"] = "BlobChannel";
            } );
            await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "Sender";
                c["Remotes:0:Name"] = "Listener";
                c["Remotes:0:Address"] = "tcp:127.0.0.1";
                c["AllowFeatures"] = "BlobChannel";
            } );
            var listenerChannel = listener.Remotes.FindRequired( sender.Local.Name ).GetRequiredFeature<CrisChannelFeature>();
            var senderChannel = sender.Remotes.FindRequired( listener.Local.Name ).GetRequiredFeature<CrisChannelFeature>();

            var listenerDirectory = listener.ServiceProvider.GetRequiredService<PocoDirectory>();
            var cmd1 = listenerDirectory.Create<ISimpleCommand>( c => c.Name = "Hello" );
            var cmd2 = listenerDirectory.Create<ISimpleGet>( c => c.Name = "World" );
            var senderDirectory = listener.ServiceProvider.GetRequiredService<PocoDirectory>();

            //var r1 = listenerChannel.TryStartVoidRequest( TestHelper.Monitor, cmd1 );
            var r2 = listenerChannel.TrySendCommand( TestHelper.Monitor, cmd2 );
        }
    }
}
