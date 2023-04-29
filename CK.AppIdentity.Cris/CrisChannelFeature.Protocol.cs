using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    public sealed partial class CrisChannelFeature
    {
        const byte DSendRequest = 1;

        /// <summary>
        /// Implements the byte[] protocol.
        /// </summary>
        sealed class Protocol : PeerProtocolHandler
        {
            readonly CrisChannelFeature _feature;

            public Protocol( CrisChannelFeature feature, ref CreateParameters createParameters )
                : base( ref createParameters )
            {
                _feature = feature;
            }

            public TransportMessage CreateRequestMessage( ActivityMonitor.DependentToken token,
                                                          IPoco? poco,
                                                          string? authToken )
            {
                var message = MessageFactory.Create( bytes =>
                {
                    FastByteWriter w = new FastByteWriter( bytes );
                    w.WriteByte( DSendRequest );
                    w.WriteString( token.ToString() );
                    w.WriteNullableString( authToken );
                    w.Commit();
                    Write( poco, bytes );
                } );
                return message;
            }

            static void Write( IPoco? poco, IBufferWriter<byte> bytes )
            {
                using( var w = new Utf8JsonWriter( bytes, new JsonWriterOptions { SkipValidation = true } ) )
                {
                    poco.Write( w );
                }
            }

            protected override bool OnSendMessage( IParallelLogger logger, ITransportMessageData message, out TransportMessage? replacement )
            {
                if( message.Source is Request r ) r.SetSentDate( DateTime.UtcNow );
                replacement = null;
                return true;
            }

            protected override ValueTask ReceiveAsync( IActivityMonitor monitor, ITransportMessage message )
            {
                HandleMessage( monitor, _feature, message.Message );
                message.Dispose();
                return default;

                static void HandleMessage( IActivityMonitor monitor,
                                           CrisChannelFeature feature,
                                           ReadOnlySequence<byte> message )
                {
                    var r = new FastByteReader( message  );
                    var discriminator = r.ReadByte();
                    switch( discriminator )
                    {
                        case DSendRequest:
                            {
                                var token = ActivityMonitor.DependentToken.Parse( r.ReadString() );
                                var authToken = r.ReadNullableString();
                                var rPoco = new Utf8JsonReader( r.GetRemainder() );
                                var payload = (ICrisPoco)feature._pocoDirectory.Read( ref rPoco )!;
                                feature._executor.Execute( feature._executorEndpoint, new CrisChannelExecutorRequest( payload, token, authToken ) );
                                break;
                            }
                    }
                }
            }
        }
    }

}
