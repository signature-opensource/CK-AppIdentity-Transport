using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer
{
    static partial class ZeroProtocol
    {
        public const int FirstAnswerMaxLength = 1 // One byte discriminator.
                                                + 5 // Number of common protocol (allows uint.MaxValue even if it's caped by MessageProtocolMap.MaxCount)
                                                + MessageProtocolMap.MaxCount * (2 * MessageProtocol.FullNameMaxLength);

        // Static messages use no initialization lock (we don't care of the rare case where 2 concurrent messages will be instantiated).
        // "1" followed by our version: it can be static.
        static TransportMessage? _downgradeProtocolReplyMessage;
        // The DiscriminatorFinalMessage with a single "1": it can be static.
        static TransportMessage? _finalSuccessMessage;
        // The DiscriminatorFinalMessage with a single "0": it can be static.
        static TransportMessage? _finalFailureMessage;
        // The DiscriminatorEvictionDisallowed: it can be static.
        static TransportMessage? _evictionDisallowedMessage;

        /// <summary>
        /// Tries to send a TransportMessage of the <see cref="TransportFeature.OutgoingInitialMessage"/> in a specific version.
        /// </summary>
        /// <param name="remote">The target remote.</param>
        /// <param name="transport">The newly created transport.</param>
        /// <param name="version">The serialization version.</param>
        /// <returns>False if <see cref="Transport.IsCondemned"/> has been signaled or if the <paramref name="version"/> is not locally supported.</returns>
        public static async ValueTask<bool> SendInitialMessageAsync( TransportFeature remote, Transport transport, int version )
        {
            // Captures the current initial message.
            var initialMessage = remote.OutgoingInitialMessage;
            Debug.Assert( initialMessage != null && initialMessage.LocalIdentities.Count > 0 );
            var m = _zeroFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                // There is currently only one version.
                Throw.CheckArgument( version == CurrentVersion );
                initialMessage.WriteCurrentVersion( ref w );
                w.Commit();
            } );
            // TODO: The message must be signed by all the currently valid identities.
            // But for this, we need to change the TransportMessage definition:
            // - IncomingTransportMessage is read only.
            // - OutgoingMessage is mutable.
            // - Prefix is managed independently of the content message.
            ComputeSHA512HashAndAppendSignatures( m, initialMessage.LocalIdentities );
            bool r = await transport.SendAsync( m ).ConfigureAwait( false );
            m.Dispose();
            return r;
        }

        static void ComputeSHA512HashAndAppendSignatures( TransportMessage m, IReadOnlyList<LocalIdentityKey> localIdentities )
        {
            Span<byte> messageHash = stackalloc byte[64];
            Span<byte> signature = stackalloc byte[256];
            ComputeHash( m.Message, messageHash );
            var w = new FastByteWriter( m.GetBufferWriter() );
            foreach( var i in localIdentities )
            {
                Throw.CheckData( i.TrySignHash( messageHash, signature, out int byteWritten ) );
                w.WriteByte( (byte)byteWritten );
                w.WriteBytes( signature );
            }
            w.Commit();
        }

        static void ComputeHash( ReadOnlySequence<byte> message, Span<byte> hash )
        {
            using var h = IncrementalHash.CreateHash( HashAlgorithmName.SHA512 );
            foreach( var s in message )
            {
                h.AppendData( s.Span );
            }
            h.GetCurrentHash( hash );
        }

        public static async ValueTask<bool> SendUnknownRemoteReplyMessageAsync( Transport transport, string? userAcceptUri )
        {
            var m = _zeroFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DNegoUnknownRemote );
                w.WriteNullableString( userAcceptUri );
                w.Commit();
            } );
            bool r = await transport.SendAsync( m ).ConfigureAwait( false );
            m.Dispose();
            return r;
        }

        public static string? ReadUnknownRemoteReplyMessage( IncomingMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DNegoUnknownRemote );
            return r.ReadNullableString();
        }

        public static ValueTask<bool> SendDowngradeProtocolReplyAsync( Transport transport )
        {
            _downgradeProtocolReplyMessage ??= _zeroFactory.CreateStatic( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DNegoDowngradeProtocol );
                w.WriteSmallUInt32( CurrentVersion );
                w.Commit();
            } );
            return transport.SendAsync( _downgradeProtocolReplyMessage );
        }

        public static int ReadDowngradeProtocolReplyMessage( IncomingMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DNegoDowngradeProtocol );
            return (int)r.ReadSmallUInt32();
        }

        public static async ValueTask<bool> SendAcceptedProtocolsMessageAsync( TransportFeature remote, Transport transport, MessageProtocolMap protocolMap )
        {
            var m = _zeroFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DNegoAcceptedProtocolsMessage );
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

        public static MessageProtocolMap TryReadAcceptedProtocolsMessage( IParallelLogger logger, IncomingMessage message, TransportFeature remote )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DNegoAcceptedProtocolsMessage );
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
                logger.Error( $"Remote '{remote.Party.FullName}' cannot support protocols: '{missing.Select( p => p.FullName ).Concatenate("' ,'")}'." );
                return default;
            }
            return MessageProtocolMap.InternalGet( protocols );
        }

        /// <summary>
        /// Message sent by the <see cref="IncomingConnectionBackTask"/> when the transport is valid
        /// but <see cref="TransportFeature.DisallowEviction"/> is false.
        /// </summary>
        /// <param name="incoming">The transport.</param>
        /// <returns>The awaitable.</returns>
        public static ValueTask<bool> SendEvictionDisallowedMessageAsync( Transport incoming )
        {
            var m = _evictionDisallowedMessage ??= _zeroFactory.CreateStatic( bytes =>
            {
                var b = bytes.GetSpan( 1 );
                b[0] = DNegoEvictionDisallowed;
            } );
            return incoming.SendAsync( m );
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
            var m = _zeroFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DNegoMissingProtocols );
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

        public static string[]? ReadMissingProtocolsMessage( IParallelLogger logger, IncomingMessage message, TransportFeature remote )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DNegoMissingProtocols );
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
                    ? _finalSuccessMessage ??= _zeroFactory.CreateStatic( bytes =>
                    {
                        var m = bytes.GetSpan( 2 );
                        m[0] = DNegoFinalMessage;
                        m[1] = 1;
                        bytes.Advance( 1 );
                    } )
                    : _finalFailureMessage ??= _zeroFactory.CreateStatic( bytes =>
                    {
                        var m = bytes.GetSpan( 2 );
                        m[0] = DNegoFinalMessage;
                        m[1] = 0;
                        bytes.Advance( 1 );
                    } );
            return transport.SendAsync( m );
        }
    }
}
