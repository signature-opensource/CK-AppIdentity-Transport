using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.Poco.Exc.Json;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
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
        static PocoJsonImportOptions _importOptions = new( PocoJsonImportOptions.ToStringDefault ) { TypeFilterName = "AllExchangeable" };

        public Protocol( CrisChannelFeature feature, ref CreateParameters createParameters )
            : base( ref createParameters )
        {
            _feature = feature;
        }

        internal bool TrySend( OutgoingCrisPoco o )
        {
            var message = MessageFactory.Create( bytes =>
            {
                FastByteWriter w = new FastByteWriter( bytes );
                w.WriteByte( DSendRequest );
                w.WriteString( o.IssuerToken.ToString() );
                w.WriteNullableString( (string?)o.ExtraData );
                w.Commit();
                Write( o.Payload, bytes );
            }, source: o );
            if( o.Payload is IEvent ? TryEnqueueHighPriority( message ) : TryEnqueue( message ) )
            {
                return true;
            }
            message.Dispose();
            return false;
        }

        protected override void OnMessageSent( IParallelLogger logger, IOutgoingMessageData message )
        {
            if( message.Source is OutgoingCrisPoco r )
            {
                r.SetSentDate( DateTime.UtcNow );
            }
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

        protected override async ValueTask ReceiveAsync( IActivityMonitor monitor, IncomingMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            switch( discriminator )
            {
                case DSendRequest:
                {
                    monitor.Debug( $"Handling incoming Cris request." );
                    var token = ActivityMonitor.Token.Parse( r.ReadString() );
                    var authToken = r.ReadNullableString();
                    var rPoco = new Utf8JsonReader( r.GetAfterHead() );
                    var command = (IAbstractCommand)_feature._pocoDirectory.ReadJson( r.GetAfterHead(), _importOptions )!;
                    break;
                }
            }
            message.Dispose();
        }
    }
}
