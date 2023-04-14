using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    partial class ZeroProtocol
    {
        /// <summary>
        /// This version drives the whole "0 Protocol" version.
        /// </summary>
        public const ushort CurrentVersion = 0;

        public const int FirstAnswerMaxLength = 1 // One byte discriminator.
                                                + 5 // Number of common protocol (allows uint.MaxValue even if it's caped by MessageProtocolMap.MaxCount)
                                                + MessageProtocolMap.MaxCount * (2 * MessageProtocol.FullNameMaxLength);

        // Static messages use no initialization lock (we don't care of the rare case where 2 concurrent messages will be instantiated).
        // "1" followed by our version: it can be static.
        static TransportMessage? _downgradeProtocolReplyMessage;
        // A single "1": it can be static.
        static TransportMessage? _finalSuccessMessage;
        // A single "0": it can be static.
        static TransportMessage? _finalFailureMessage;

        /// <summary>
        /// Tries to send a TransportMessage of the <see cref="TransportFeature.OutgoingInitialMessage"/> in a specific version.
        /// </summary>
        /// <param name="remote">The target remote.</param>
        /// <param name="transport">The newly created transport.</param>
        /// <param name="version">The serialization version.</param>
        /// <returns>False if <see cref="Transport.IsCondemned"/> has been signaled or if the <paramref name="version"/> is not locally supported.</returns>
        public static async ValueTask<bool> SendInitialMessageAsync( TransportFeature remote, Transport transport, int version )
        {
            Debug.Assert( remote.OutgoingInitialMessage != null );
            var m = OutgoingMessageFactory.ZeroProtocol.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                // There is currently only one version.
                Throw.CheckArgument( version == CurrentVersion );
                remote.OutgoingInitialMessage.WriteCurrentVersion( ref w );
                w.Commit();
            } );
            bool r = await transport.SendAsync( m ).ConfigureAwait( false );
            m.Dispose();
            return r;
        }

        public static async ValueTask<bool> SendUnknownRemoteReplyMessageAsync( Transport transport, string? userAcceptUri )
        {
            var m = OutgoingMessageFactory.ZeroProtocol.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 0 );
                w.WriteNullableString( userAcceptUri );
                w.Commit();
            } );
            bool r = await transport.SendAsync( m ).ConfigureAwait( false );
            m.Dispose();
            return r;
        }

        public static string? ReadUnknownRemoteReplyMessageAsync( TransportMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == 0 );
            return r.ReadNullableString();
        }

        public static ValueTask<bool> SendDowngradeProtocolReplyAsync( Transport transport )
        {
            _downgradeProtocolReplyMessage ??= OutgoingMessageFactory.ZeroProtocol.CreateStatic( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 1 );
                w.WriteSmallUInt32( CurrentVersion );
                w.Commit();
            } );
            return transport.SendAsync( _downgradeProtocolReplyMessage );
        }

        public static int ReadDowngradeProtocolReplyMessage( TransportMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == 1 );
            return (int)r.ReadSmallUInt32();
        }

        public static async ValueTask<bool> SendAcceptedMessageAsync( TransportFeature remote, Transport transport, MessageProtocolMap protocolMap )
        {
            var m = OutgoingMessageFactory.ZeroProtocol.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 2 );
                w.WriteSmallUInt32( (uint)protocolMap.Protocols.Count );
                foreach( var p in protocolMap.Protocols )
                {
                    w.WriteString( p.FullName );
                }
                w.Commit();
            } );
            bool r = await transport.SendAsync( m ).ConfigureAwait( false );
            m.Dispose();
            return r;
        }

        public static MessageProtocolMap TryReadAcceptedMessage( IActivityLogger logger, TransportMessage message, TransportFeature remote )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == 2 );
            uint count = r.ReadSmallUInt32();
            if( count > MessageProtocolMap.MaxCount )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' returned {count} protocols, MessageProtocolMap.MaxCount is {MessageProtocolMap.MaxCount}." );
                return default;
            }
            // A valid answer is composed only of different protocol names (a single version per protocol) and
            // all our BestRegisteredProtocols must be satisfied (may be with an old version).
            var protocols = new MessageProtocol[count];
            for( int i = 0; i < count; ++i )
            {
                var fullName = r.ReadString( MessageProtocol.FullNameMaxLength );
                var p = remote.RegisteredProtocols.FirstOrDefault( p => p.FullName.Equals( fullName, StringComparison.OrdinalIgnoreCase ) );
                if( p == null )
                {
                    logger.Error( $"Remote '{remote.Party.FullName}' returned an unwanted protocol '{fullName}'." );
                    return default;
                }
                protocols[i] = p;
            }
            var missing = remote.BestRegisteredProtocols.Where( b => !protocols.Any( p => p.Name == b.Name ) );
            if( missing.Any() )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' cannot support protocols: '{missing.Select( p => p.FullName ).Concatenate()}'." );
                return default;
            }
            return MessageProtocolMap.InternalGet( protocols );
        }

        /// <summary>
        /// Message sent by the <see cref="IncomingConnectionBackTask"/> when the initial message of the remote misses some
        /// of our protocols.
        /// </summary>
        /// <param name="incoming">The transport.</param>
        /// <param name="missingProtocols">The missing protocols.</param>
        /// <returns>The awaitable.</returns>
        public static async ValueTask<bool> SendMissingProtocolsMessageAsync( Transport incoming, IReadOnlyList<MessageProtocol> missingProtocols )
        {
            var m = OutgoingMessageFactory.ZeroProtocol.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 3 );
                w.WriteSmallUInt32( (uint)missingProtocols.Count );
                foreach( var p in missingProtocols )
                {
                    w.WriteString( p.FullName );
                }
                w.Commit();
            } );
            bool r = await incoming.SendAsync( m ).ConfigureAwait( false );
            m.Dispose();
            return r;
        }

        public static string[]? ReadMissingProtocolsMessage( IActivityLogger logger, TransportMessage message, TransportFeature remote )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == 3 );
            uint count = r.ReadSmallUInt32();
            if( count > MessageProtocolMap.MaxCount )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' returned {count} missing protocols, MessageProtocolMap.MaxCount is {MessageProtocolMap.MaxCount}." );
                return null;
            }
            var missingProtocols = new string[count];
            for( int i = 0; i < count; ++i )
            {
                missingProtocols[i] = r.ReadString( MessageProtocol.FullNameMaxLength );
            }
            return missingProtocols;
        }

        public static ValueTask<bool> SendFinalMessageAsync( Transport transport, TransportFeature remote, bool value )
        {
            TransportMessage m = value
                    ? _finalSuccessMessage ??= OutgoingMessageFactory.ZeroProtocol.CreateStatic( bytes =>
                    {
                        var m = bytes.GetSpan( 1 );
                        m[0] = 1;
                        bytes.Advance( 1 );
                    } )
                    : _finalFailureMessage ??= OutgoingMessageFactory.ZeroProtocol.CreateStatic( bytes =>
                    {
                        var m = bytes.GetSpan( 1 );
                        m[0] = 0;
                        bytes.Advance( 1 );
                    } );
            return transport.SendAsync( m );
        }
    }
}
