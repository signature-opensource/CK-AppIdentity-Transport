using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    static class ZeroProtocol
    {
        public const int FirstAnswerMaxLength = 1 // One byte discriminator.
                                                + 5 // Number of common protocol (allows uint.MaxValue even if it's caped by MessageProtocolMap.MaxCount)
                                                + MessageProtocolMap.MaxCount * (2 * MessageProtocol.NameMaxLength );

        // "1" followed by our version: it can be static.
        static TransportMessage? _downgradeProtocolReplyMessage;

        /// <summary>
        /// Tries to send a TransportMessage of the <see cref="TransportFeature.OutgoingInitialMessage"/> in a specific version.
        /// </summary>
        /// <param name="remote">The target remote.</param>
        /// <param name="transport">The newly created transport.</param>
        /// <param name="version">The serialization version.</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>False if <paramref name="cancellation"/> has been signaled or if the <paramref name="version"/> is not locally supported.</returns>
        public static ValueTask<bool> SendInitialMessageAsync( TransportFeature remote, Transport transport, int version, CancellationToken cancellation )
        {
            Debug.Assert( remote.OutgoingInitialMessage != null );
            using var m = OutgoingMessageFactory.ZeroProtocol.Create( MessageProtocol.ZeroProtocol, bytes =>
            {
                var w = new FastByteWriter( bytes );
                // There is currently only one version.
                Throw.CheckArgument( version == InitialMessage.CurrentVersion );
                remote.OutgoingInitialMessage.WriteCurrentVersion( ref w );
                w.Commit();
            } );
            return transport.SendAsync( m, cancellation );
        }

        public static Task SendUnknownRemoteReplyMessageAsync( Transport transport, string? userAcceptUri )
        {
            using var m = OutgoingMessageFactory.ZeroProtocol.Create( MessageProtocol.ZeroProtocol, bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 0 );
                w.WriteNullableString( userAcceptUri );
                w.Commit();
            } );
            return transport.SendAsync( m ).AsTask();
        }

        public static string? ReadUnknownRemoteReplyMessageAsync( TransportMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == 0 );
            return r.ReadNullableString();
        }

        public static Task SendDowngradeProtocolReplyAsync( Transport transport )
        {
            _downgradeProtocolReplyMessage ??= OutgoingMessageFactory.ZeroProtocol.CreateStatic( MessageProtocol.ZeroProtocol, bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 1 );
                w.WriteSmallUInt32( InitialMessage.CurrentVersion );
                w.Commit();
            } );
            return transport.SendAsync( _downgradeProtocolReplyMessage ).AsTask();
        }

        public static int ReadDowngradeProtocolReplyMessage( TransportMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == 1 );
            return (int)r.ReadSmallUInt32();
        }

        public static Task SendAcceptedMessageAsync( TransportFeature remote, Transport transport, MessageProtocolMap protocolMap )
        {
            using var m = OutgoingMessageFactory.ZeroProtocol.Create( MessageProtocol.ZeroProtocol, bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 2 );
                w.WriteSmallUInt32( (uint)protocolMap.Protocols.Count );
                foreach( var p in protocolMap.Protocols )
                {
                    w.WriteString( p.Name );
                }
                w.Commit();
            } );
            return transport.SendAsync( m ).AsTask();
        }

        public static MessageProtocolMap TryReadAcceptedMessage( IActivityLogger logger, TransportMessage message, TransportFeature remote )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == 2 );
            uint count = r.ReadSmallUInt32();
            if( count <= MessageProtocolMap.MaxCount )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' returned {count} protocols, MessageProtocolMap.MaxCount is {MessageProtocolMap.MaxCount}." );
                return default;
            }
            var protocols = new MessageProtocol[count];
            for( int i = 0; i < count; ++i )
            {
                var name = r.ReadString();
                var p = remote.AvailableProtocols.FirstOrDefault( p => p.Name == name );
                if( !p.IsValid )
                {
                    logger.Error( $"Remote '{remote.Party.FullName}' returned an unknown protocol '{name}'." );
                }
                protocols[i] = p;
            }
            return MessageProtocolMap.InternalGet( protocols );
        }

    }
}
