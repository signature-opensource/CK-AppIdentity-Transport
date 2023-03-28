using FluentAssertions;
using NUnit.Framework;
using System;
using System.Buffers;

namespace CK.AppIdentity.TransportLayer.Tests
{
    [TestFixture]
    public class TransportMessageTests
    {
        sealed class Context : IDisposable
        {
            public readonly MessageProtocolDirectoryService ProtocolDirectory;
            public readonly MessageProtocol TestProtocol;
            public readonly MessageProtocolMap TestMap;
            public readonly OutgoingMessageFactory Outgoing;
            public readonly IncomingMessageFactory Incoming;

            public Context()
            {
                ProtocolDirectory = new MessageProtocolDirectoryService();
                TestProtocol = ProtocolDirectory.Register( "Test" );
                TestMap = MessageProtocolMap.Get( TestProtocol );
                Outgoing = new OutgoingMessageFactory( TestMap );
                Incoming = new IncomingMessageFactory( TestMap );
            }

            public void Dispose()
            {
                Outgoing.Dispose();
                Incoming.Dispose();
            }
        }


        [Test]
        public async Task basic_TransportMessage_read_write( )
        {
            using var ctx = new Context();

            for( int i = 4091; i < 5000; ++i )
            {
                await WriteAndReadAsync( ctx.TestProtocol, ctx.Outgoing, ctx.Incoming, i );
            }

            static async Task WriteAndReadAsync( MessageProtocol protocol, OutgoingMessageFactory outgoing, IncomingMessageFactory incoming, int lenString )
            {
                using var m = outgoing.Create( protocol, bytes =>
                {
                    var w = new FastByteWriter( bytes );
                    w.WriteString( new string( 'A', lenString ) );
                    w.Commit();
                } );

                var reader = new BasicAsyncReader( m );
                using var mBack = await incoming.ReadAsync( reader.ReadExactlyAsync );

                mBack.IsValid.Should().BeTrue();
                mBack.Protocol.Should().Be( m.Protocol );
                mBack.WireMessage.Length.Should().Be( m.WireMessage.Length );
                mBack.Message.Length.Should().Be( m.Message.Length );
                mBack.WireMessage.ToArray().Should().BeEquivalentTo( m.WireMessage.ToArray() );
            }

        }

        [TestCase( 3712, 10 )]
        [TestCase( 21, 259 )]
        [TestCase( 274, 48527 )]
        [TestCase( 274, 90500 )]
        public async Task random_TransportMessage_read_write( int seed, int maxMessageLength )
        {
            using var ctx = new Context();

            var random = new Random( seed );
            var buffer = new byte[maxMessageLength];
            random.NextBytes( buffer.AsSpan() );

            for( var i = 0; i < 100; ++i )
            {
                await WriteAndReadAsync( ctx.TestProtocol, ctx.Outgoing, ctx.Incoming, buffer, random );
            }

            static async Task WriteAndReadAsync( MessageProtocol protocol, OutgoingMessageFactory outgoing, IncomingMessageFactory incoming, byte[] buffer, Random random )
            {
                using var m = outgoing.Create( protocol, bytes =>
                {
                    var w = new FastByteWriter( bytes );
                    int len = random.Next( buffer.Length - 1 ) + 1;
                    w.WriteBytes( buffer.AsSpan( 0, len ) );
                    w.Commit();
                } );

                var reader = new BasicAsyncReader( m );
                using var mBack = await incoming.ReadAsync( reader.ReadExactlyAsync ).ConfigureAwait( false );

                mBack.IsValid.Should().BeTrue();
                mBack.Protocol.Should().Be( m.Protocol );
                mBack.WireMessage.ToArray().Should().BeEquivalentTo( m.WireMessage.ToArray() );
            }
        }
    }
}
