using CK.AppIdentity.TransportLayer;
using CK.Core;
using System.Buffers;
using System.Text.Json;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    public sealed partial class CrisEndPointFeature
    {
        /// <summary>
        /// Implements the byte[] protocol.
        /// </summary>
        sealed class Protocol : PeerProtocolHandler
        {
            readonly CrisEndPointFeature _feature;
            // Static TransportMessage: Dispose() is ignored.
            TransportMessage? _nullPoco;

            public Protocol( CrisEndPointFeature feature, ref CreateParameters createParameters )
                : base( ref createParameters )
            {
                _feature = feature;
            }

            public TransportMessage CreateRequestMessage( ActivityMonitor.DependentToken dependentToken, IPoco? poco, string? authToken )
            {
                if( poco == null )
                {
                    return _nullPoco ??= MessageFactory.CreateStatic( bytes => Write( poco, bytes ) );
                }
                var message = MessageFactory.Create( bytes => Write( poco, bytes ) );
                message.Source = poco;
                return message;
            }

            static void Write( IPoco? poco, IBufferWriter<byte> bytes )
            {
                using( var w = new Utf8JsonWriter( bytes, new JsonWriterOptions { SkipValidation = true } ) )
                {
                    poco.Write( w );
                }
            }

            protected override async ValueTask ReceiveAsync( IActivityMonitor monitor, ITransportMessage message )
            {
                var poco = Deserialize( _feature._pocoDirectory, message.Message );
                message.Dispose();
                //await _feature._received.SafeRaiseAsync( monitor, _feature, poco );

                static IPoco? Deserialize( PocoDirectory pocoDirectory, ReadOnlySequence<byte> message )
                {
                    var r = new Utf8JsonReader( message );
                    return pocoDirectory.Read( ref r );
                }
            }
        }
    }

}
