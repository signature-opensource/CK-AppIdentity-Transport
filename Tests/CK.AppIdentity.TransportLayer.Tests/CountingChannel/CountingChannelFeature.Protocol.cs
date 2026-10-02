using CK.Core;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

public sealed partial class CountingChannelFeature
{
    sealed class Protocol : PeerProtocolHandler
    {
        readonly CountingChannelFeature _feature;

        public Protocol( CountingChannelFeature feature, ref CreateParameters createParameters )
            : base( ref createParameters )
        {
            _feature = feature;
        }

        public IOutgoingMessage CreateMessage( int id )
        {
            return MessageFactory.Create( bytes =>
            {
                var s = bytes.GetSpan( 4 );
                BinaryPrimitives.WriteInt32LittleEndian( s, id );
                bytes.Advance( 4 );
            }, source: id );
        }

        protected override bool OnSendMessage( IParallelLogger logger, IOutgoingMessageData message, out IOutgoingMessage? replacement )
        {
            replacement = null;
            int id = (int)message.Source!;
            _feature._attempts.AddOrUpdate( id, 1, ( _, c ) => c + 1 );
            if( id == _feature.GatedId )
            {
                // Park the send loop here. The message is peeked but not yet written: this is the
                // state the transport must be able to die in without the message being lost.
                _feature.GateEntered.Set();
                _feature.SendGate.Wait( 20_000 );
            }
            if( id == _feature.ThrowOnSendId )
            {
                throw new CKException( $"OnSendMessage for {id}." );
            }
            return id != _feature.SkippedId;
        }

        protected override void OnMessageSent( IParallelLogger logger, IOutgoingMessageData message )
        {
            int id = (int)message.Source!;
            _feature._sent.AddOrUpdate( id, 1, ( _, c ) => c + 1 );
            if( _feature.ThrowOnMessageSent )
            {
                throw new CKException( $"OnMessageSent for {id}." );
            }
        }

        protected override ValueTask ReceiveAsync( IActivityMonitor monitor, IncomingMessage message )
        {
            Span<byte> b = stackalloc byte[4];
            message.Message.Slice( 0, 4 ).CopyTo( b );
            message.Dispose();
            int id = BinaryPrimitives.ReadInt32LittleEndian( b );
            if( id == _feature.ThrowOnReceiveId )
            {
                throw new CKException( $"ReceiveAsync for {id}." );
            }
            _feature._received.Enqueue( id );
            return default;
        }
    }
}
