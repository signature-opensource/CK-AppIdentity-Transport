using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.Poco.Exc.Json;
using System;
using System.Buffers;
using System.Text.Json;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

public sealed partial class CrisChannelFeature
{
    const byte DSendRequest = 1;
    const byte DValidationResult = 2;
    const byte DRequestResult = 3;
    const byte DEvent = 4;

    /// <summary>
    /// Implements the byte[] protocol.
    /// </summary>
    sealed class Protocol : PeerProtocolHandler
    {
        readonly CrisChannelFeature _feature;

        static PocoJsonExportOptions _exportOptions = new( PocoJsonExportOptions.ToStringDefault ) { TypeFilterName = "AllExchangeable" };

        public Protocol( CrisChannelFeature feature, ref CreateParameters createParameters )
            : base( ref createParameters )
        {
            _feature = feature;
        }

        internal bool TrySendRequest( OutgoingCommand request, bool highPriority )
        {
            var message = MessageFactory.Create( bytes =>
            {
                FastByteWriter w = new FastByteWriter( bytes );
                w.WriteByte( DSendRequest );
                w.WriteString( request.IssuerToken.ToString() );
                w.WriteNullableString( (string?)request.ExtraData );
                w.Commit();
                Write( request.Payload, bytes );
            }, source: request );
            if( highPriority ? TryEnqueueHighPriority( message ) : TryEnqueue( message ) )
            {
                return true;
            }
            message.Dispose();
            return false;
        }

        protected override bool OnSendMessage( IParallelLogger logger, IOutgoingMessageData message, out IOutgoingMessage? replacement )
        {
            if( message.Source is OutgoingCommand r ) r.SetSentDate( logger, DateTime.UtcNow );
            replacement = null;
            return true;
        }

        internal bool TrySendValidationMessage( ActivityMonitor.LogKey id, CrisValidationResult validationResult )
        {
            var message = MessageFactory.Create( bytes =>
            {
                FastByteWriter w = new FastByteWriter( bytes );
                w.WriteByte( DValidationResult );
                w.WriteReadLogKey( id );
                w.WriteCrisValidationResult( validationResult );
                w.Commit();
            } );
            if( TryEnqueueHighPriority( message ) )
            {
                return true;
            }
            message.Dispose();
            return false;
        }

        //internal bool TrySendResult( ActivityMonitor.LogKey id, CrisExecutionHost.ICrisJobResult? result )
        //{
        //    var message = MessageFactory.Create( bytes =>
        //    {
        //        FastByteWriter w = new FastByteWriter( bytes );
        //        w.WriteByte( DRequestResult );
        //        w.WriteReadLogKey( id );
        //        w.Commit();
        //        Write( result, bytes );
        //    } );
        //    if( TryEnqueueHighPriority( message ) )
        //    {
        //        return true;
        //    }
        //    message.Dispose();
        //    return false;
        //}

        internal bool TrySendCommandEvent( ActivityMonitor.LogKey id, IEvent e )
        {
            var message = MessageFactory.Create( bytes =>
            {
                FastByteWriter w = new FastByteWriter( bytes );
                w.WriteByte( DEvent );
                w.WriteReadLogKey( id );
                w.Commit();
                Write( e, bytes );
            } );
            if( TryEnqueueHighPriority( message ) )
            {
                return true;
            }
            message.Dispose();
            return false;
        }

        void Write( IPoco poco, IBufferWriter<byte> bytes )
        {
            using( var w = new Utf8JsonWriter( bytes, _exportOptions.WriterOptions ) )
            {
                poco.WriteJson( w, new PocoJsonWriteContext( _feature._pocoDirectory, _exportOptions ) );
            }
        }

        //protected override ValueTask ReceiveAsync( IActivityMonitor monitor, ITransportMessage message )
        //{
        //    HandleMessage( monitor, _feature, message.Message );
        //    message.Dispose();
        //    return default;

        //    static void HandleMessage( IActivityMonitor monitor,
        //                               CrisChannelFeature feature,
        //                               ReadOnlySequence<byte> message )
        //    {
        //        var r = new FastByteReader( message  );
        //        var discriminator = r.ReadByte();
        //        switch( discriminator )
        //        {
        //            case DSendRequest:
        //                {
        //                    monitor.Debug( $"Handling incoming Cris request." );
        //                    var token = ActivityMonitor.Token.Parse( r.ReadString() );
        //                    var authToken = r.ReadNullableString();
        //                    var rPoco = new Utf8JsonReader( r.GetRemainder() );
        //                    var payload = (IAbstractCommand)feature._pocoDirectory.Read( ref rPoco )!;
        //                    feature._executor.BackgroundExecute( feature._executorEndpoint, new CrisChannelExecutorRequest( payload, token, authToken ) );
        //                    break;
        //                }
        //            case DValidationResult:
        //                {
        //                    monitor.Debug( $"Handling Cris validation message." );
        //                    feature._outgoingRequestCache.SetValidationResult( monitor.ParallelLogger, r.ReadLogKey(), r.ReadCrisValidationResult() );
        //                    break;
        //                }
        //            case DEvent:
        //                {
        //                    monitor.Debug( $"Handling Cris event message." );
        //                    var id = r.ReadLogKey();
        //                    var rPoco = new Utf8JsonReader( r.GetRemainder() );
        //                    var e = (IEvent)feature._pocoDirectory.Read( ref rPoco )!;
        //                    feature._outgoingRequestCache.CollectCommandEvent( monitor, id, e );
        //                    break;
        //                }
        //            case DRequestResult:
        //                {
        //                    monitor.Debug( $"Handling Cris request result." );
        //                    var id = r.ReadLogKey();
        //                    var rPoco = new Utf8JsonReader( r.GetRemainder() );
        //                    var result = (CrisExecutor.ICrisExecutorPayload)feature._pocoDirectory.Read( ref rPoco )!;
        //                    feature._outgoingRequestCache.SetResult( monitor.ParallelLogger, id, result.Result );
        //                    break;
        //                }
        //        }
        //    }
        //}

        protected override ValueTask ReceiveAsync( IActivityMonitor monitor, IncomingMessage message )
        {
            throw new NotImplementedException();
        }
    }
}
