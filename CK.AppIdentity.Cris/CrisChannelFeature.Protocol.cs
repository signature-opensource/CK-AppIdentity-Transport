using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.Poco.Exc.Json;
using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

public sealed partial class CrisChannelFeature
{
    // Caller to callee: the issuer token and the typed command.
    const byte DCommand = 1;
    // Callee to caller: the issuer token key and a typed immediate event.
    const byte DImmediateEvent = 2;
    // Callee to caller: the issuer token key and the untyped ICrisCallResult.
    const byte DExecuted = 3;

    /// <summary>
    /// Implements the Cris protocol. A message starts with one of the D* discriminators.
    /// <para>
    /// The answers (immediate events and final result) are sent on the high priority queue: they are
    /// small, never block the runner that executes the command and keep their relative order.
    /// </para>
    /// </summary>
    internal sealed class Protocol : PeerProtocolHandler
    {
        readonly CrisChannelFeature _feature;

        static readonly PocoJsonExportOptions _exportOptions = new( PocoJsonExportOptions.ToStringDefault ) { TypeFilterName = "AllExchangeable" };
        static readonly PocoJsonImportOptions _importOptions = new( PocoJsonImportOptions.ToStringDefault ) { TypeFilterName = "AllExchangeable" };

        public Protocol( CrisChannelFeature feature, ref CreateParameters createParameters )
            : base( ref createParameters )
        {
            _feature = feature;
        }

        internal IOutgoingMessage CreateCommandMessage( ExecutingCommand c )
        {
            return MessageFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DCommand );
                w.WriteString( c.IssuerToken.ToString() );
                w.Commit();
                _feature._pocoDirectory.WriteJson( bytes, c.Command, withType: true, _exportOptions );
            }, source: c );
        }

        internal void SendImmediateEvent( IActivityMonitor monitor, ActivityMonitor.LogKey key, IEvent e )
        {
            IOutgoingMessage message;
            try
            {
                message = MessageFactory.Create( bytes =>
                {
                    var w = new FastByteWriter( bytes );
                    w.WriteByte( DImmediateEvent );
                    w.WriteLogKey( key );
                    w.Commit();
                    _feature._pocoDirectory.WriteJson( bytes, e, withType: true, _exportOptions );
                } );
            }
            catch( Exception ex )
            {
                monitor.Error( $"Unable to serialize immediate event '{e.CrisPocoModel.PocoName}' for '{_feature.Party.FullName}'. It is not sent.", ex );
                return;
            }
            Enqueue( monitor, message );
        }

        internal void SendExecuted( IActivityMonitor monitor, ActivityMonitor.LogKey key, object? result, ImmutableArray<UserMessage> validationMessages )
        {
            var callResult = _feature._callResultFactory.Create( r =>
            {
                r.Result = result;
                if( !validationMessages.IsDefaultOrEmpty ) r.ValidationMessages = [.. validationMessages];
            } );
            IOutgoingMessage message;
            try
            {
                message = CreateExecutedMessage( key, callResult );
            }
            catch( Exception ex )
            {
                monitor.Error( $"Unable to serialize the result for '{_feature.Party.FullName}'. Sending an error instead.", ex );
                message = CreateExecutedMessage( key, CreateError( "Unable to serialize the command result." ) );
            }
            Enqueue( monitor, message );
        }

        void SendError( IActivityMonitor monitor, ActivityMonitor.LogKey key, string error )
        {
            Enqueue( monitor, CreateExecutedMessage( key, CreateError( error ) ) );
        }

        ICrisCallResult CreateError( string message )
        {
            return _feature._callResultFactory.Create( r => r.Result = _feature._errorFactory.Create( e => e.Errors.Add(
                new UserMessage( UserMessageLevel.Error, MCString.CreateNonTranslatable( NormalizedCultureInfo.CodeDefault, message ) ) ) ) );
        }

        IOutgoingMessage CreateExecutedMessage( ActivityMonitor.LogKey key, ICrisCallResult callResult )
        {
            return MessageFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DExecuted );
                w.WriteLogKey( key );
                w.Commit();
                _feature._pocoDirectory.WriteJson( bytes, callResult, withType: false, _exportOptions );
            } );
        }

        void Enqueue( IActivityMonitor monitor, IOutgoingMessage message )
        {
            if( !TryEnqueueHighPriority( message ) )
            {
                message.Dispose();
                monitor.Warn( $"Remote '{_feature.Party.FullName}' is no more available. Answer is lost." );
            }
        }

        protected override ValueTask ReceiveAsync( IActivityMonitor monitor, IncomingMessage message )
        {
            // Everything is read before the message is released: only the
            // dispatch of an immediate event may complete asynchronously.
            try
            {
                return Handle( monitor, message.Message );
            }
            finally
            {
                message.Dispose();
            }
        }

        ValueTask Handle( IActivityMonitor monitor, ReadOnlySequence<byte> message )
        {
            var r = new FastByteReader( message );
            switch( r.ReadByte() )
            {
                case DCommand:
                    HandleCommand( monitor, ref r );
                    return default;
                case DImmediateEvent:
                    return HandleImmediateEvent( monitor, ref r );
                case DExecuted:
                    HandleExecuted( monitor, ref r );
                    return default;
                default:
                    monitor.Error( $"Invalid Cris message received from '{_feature.Party.FullName}'. Ignored." );
                    return default;
            }
        }

        void HandleCommand( IActivityMonitor monitor, ref FastByteReader r )
        {
            if( !ActivityMonitor.Token.TryParse( r.ReadString(), out var token ) )
            {
                // Without the token, there is no key to answer to.
                monitor.Error( $"Invalid issuer token in a command received from '{_feature.Party.FullName}'. Ignored." );
                return;
            }
            IAbstractCommand? command = null;
            try
            {
                command = _feature._pocoDirectory.ReadJson( r.GetAfterHead(), _importOptions ) as IAbstractCommand;
                if( command == null )
                {
                    monitor.Error( $"Received a Poco that is not a command from '{_feature.Party.FullName}'." );
                }
            }
            catch( Exception ex )
            {
                monitor.Error( $"Unable to read a command received from '{_feature.Party.FullName}'.", ex );
            }
            if( command == null )
            {
                SendError( monitor, token.Key, "Unable to read the command." );
                return;
            }
            _feature._executor.Execute( this, command, token );
        }

        ValueTask HandleImmediateEvent( IActivityMonitor monitor, ref FastByteReader r )
        {
            var key = r.ReadLogKey();
            IEvent? e = null;
            try
            {
                e = _feature._pocoDirectory.ReadJson( r.GetAfterHead(), _importOptions ) as IEvent;
            }
            catch( Exception ex )
            {
                monitor.Error( $"Unable to read an immediate event received from '{_feature.Party.FullName}'. Ignored.", ex );
                return default;
            }
            if( e == null )
            {
                monitor.Error( $"Received a Poco that is not an event from '{_feature.Party.FullName}'. Ignored." );
                return default;
            }
            return new ValueTask( _feature.OnImmediateEventAsync( monitor, key, e ) );
        }

        void HandleExecuted( IActivityMonitor monitor, ref FastByteReader r )
        {
            var key = r.ReadLogKey();
            ICrisCallResult? result = null;
            try
            {
                result = _feature._callResultFactory.ReadJson( r.GetAfterHead(), _importOptions );
            }
            catch( Exception ex )
            {
                monitor.Error( $"Unable to read the result of command '{key}' received from '{_feature.Party.FullName}'.", ex );
            }
            _feature.OnExecuted( monitor, key, result );
        }
    }
}
