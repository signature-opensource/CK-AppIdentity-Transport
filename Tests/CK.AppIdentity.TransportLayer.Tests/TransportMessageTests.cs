using FluentAssertions;
using NUnit.Framework;
using System;
using System.Buffers;

namespace CK.AppIdentity.TransportLayer.Tests
{
    [TestFixture]
    public class TransportMessageTests
    {
        [Test]
        public async Task basic_TransportMessage_read_write( )
        {
            var outgoing = new OutgoingMessageFactory( 1 );
            var incoming = new IncomingMessageFactory();

            for( int i = 4091; i < 5000; ++i )
            {
                await WriteAndReadAsync( outgoing, incoming, i );
            }

            static async Task WriteAndReadAsync( OutgoingMessageFactory outgoing, IncomingMessageFactory incoming, int lenString )
            {
                using var m = outgoing.Create( bytes =>
                {
                    var w = new FastByteWriter( bytes );
                    w.WriteString( new string( 'A', lenString ) );
                    w.Commit();
                } );

                var reader = new BasicAsyncReader( m );
                using var mBack = await incoming.ReadAsync( reader.ReadExactlyAsync );

                mBack.IsValid.Should().BeTrue();
                mBack.ProtocolNumber.Should().Be( m.ProtocolNumber );
                mBack.WireMessage.Length.Should().Be( m.WireMessage.Length );
                mBack.Message.Length.Should().Be( m.Message.Length );
                mBack.WireMessage.ToArray().Should().BeEquivalentTo( m.WireMessage.ToArray() );
            }

        }

        [TestCase( 3712, 10 )]
        [TestCase( 21, 259 )]
        [TestCase( 274, 48527 )]
        public async Task random_TransportMessage_read_write( int seed, int maxMessageLength )
        {
            var outgoing = new OutgoingMessageFactory( 1 );
            var incoming = new IncomingMessageFactory();

            var random = new Random( seed );
            var buffer = new byte[maxMessageLength];

            for( var i = 0; i < 1000; ++i )
            {
                await WriteAndReadAsync( outgoing, incoming, buffer, random );
            }

            static async Task WriteAndReadAsync( OutgoingMessageFactory outgoing, IncomingMessageFactory incoming, byte[] buffer, Random random )
            {
                using var m = outgoing.Create( bytes =>
                {
                    var w = new FastByteWriter( bytes );
                    int len = random.Next( buffer.Length - 1 ) + 1;
                    random.NextBytes( buffer.AsSpan( 0, len ) );
                    w.WriteBytes( buffer );
                    w.Commit();
                } );

                var reader = new BasicAsyncReader( m );
                using var mBack = await incoming.ReadAsync( reader.ReadExactlyAsync );

                mBack.IsValid.Should().BeTrue();
                mBack.ProtocolNumber.Should().Be( m.ProtocolNumber );
                mBack.WireMessage.ToArray().Should().BeEquivalentTo( m.WireMessage.ToArray() );
            }
        }
    }
}
