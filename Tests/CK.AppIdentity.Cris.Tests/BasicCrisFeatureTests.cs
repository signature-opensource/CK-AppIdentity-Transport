using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using FluentAssertions;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
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

        [TestCase(false)]
        public async Task simple_exchange_Async( bool withHandlers )
        {
            var types = new[] { typeof( ISimpleCommand ), typeof( ISimpleGet ) };
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "Listener";
                c["Remotes:0:Name"] = "Sender";
                c["AllowFeatures"] = "BlobChannel";
            }, types: types );
            await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "Sender";
                c["Remotes:0:Name"] = "Listener";
                c["Remotes:0:Address"] = "tcp:127.0.0.1";
                c["AllowFeatures"] = "BlobChannel";
            }, types: types );

            var listenerChannel = listener.Remotes.FindRequired( sender.Local.Name ).GetRequiredFeature<CrisChannelFeature>();
            var senderChannel = sender.Remotes.FindRequired( listener.Local.Name ).GetRequiredFeature<CrisChannelFeature>();

            var listenerDirectory = listener.ServiceProvider.GetRequiredService<PocoDirectory>();
            var cmd1 = listenerDirectory.Create<ISimpleCommand>( c => c.Name = "Hello" );

            var r1 = listenerChannel.SendCommand( TestHelper.Monitor, cmd1 );
            Debug.Assert( r1 != null );
            var result1 = (await r1.RequestCompletion) as ICrisResultError;
            Debug.Assert( result1 != null );
            result1.Errors.Should().Contain( "No Command handler found." );

            var senderDirectory = listener.ServiceProvider.GetRequiredService<PocoDirectory>();
            var cmd2 = senderDirectory.Create<ISimpleGet>( c => c.Name = "World" );
            var r2 = senderChannel.SendCommand( TestHelper.Monitor, cmd1 );
            Debug.Assert( r2 != null );
            var result2 = (await r2.RequestCompletion) as ICrisResultError;
            Debug.Assert( result2 != null );
            result2.Errors.Should().Contain( "No Command handler found." );
        }
    }
}
