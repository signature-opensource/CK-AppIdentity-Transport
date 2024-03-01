using CK.AppIdentity.TransportLayer;
using CK.Core;
using System.Buffers;

namespace CK.AppIdentity.BlobChannel
{
    public sealed partial class BlobChannelFeature
    {
        /// <summary>
        /// Implements the byte[] protocol.
        /// </summary>
        sealed class Protocol : PeerProtocolHandler
        {
            readonly BlobChannelFeature _feature;

            public Protocol( BlobChannelFeature feature, ref CreateParameters createParameters )
                : base( ref createParameters )
            {
                _feature = feature;
            }

            public IOutgoingMessage CreateMessage( byte[] data )
            {
                // Here we are using the MutableSequence<byte>.AddSegment( byte[] ): there
                // is no copy at all, the data is simply referenced by the sequence.
                OutgoingMessageBuilder builder = MessageFactory.CreateBuilder();
                MutableSequence<byte> w = builder.ObtainSequence();
                w.AddSegment( data );
                builder.Source = data;
                return builder.CreateMessage( w );
            }

            protected override async ValueTask ReceiveAsync( IActivityMonitor monitor, IncomingMessage message )
            {
                // We take a snapshot of the data in a new array because a receiver must dispose the message
                // and this is a simple channel: we don't want to expose a message that can be retained
                // by the event subscribers (but we could...).
                byte[] payload = message.Message.ToArray();
                message.Dispose();
                await _feature._received.SafeRaiseAsync( monitor, _feature, payload );
            }
        }
}

}
