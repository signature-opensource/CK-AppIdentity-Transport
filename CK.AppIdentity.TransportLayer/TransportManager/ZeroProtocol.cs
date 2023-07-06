using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Diagnostics;
using System.Text;

namespace CK.AppIdentity.TransportLayer
{
    static partial class ZeroProtocol
    {
        /// <summary>
        /// This version drives the whole "0 Protocol" version.
        /// </summary>
        public const ushort CurrentVersion = 0;

        // Discriminator byte is the first byte of the payload.
        // Negotiation discriminators:
        internal const byte DNegoUnknownRemote = 0;
        internal const byte DNegoFinalMessage = 1;
        internal const byte DNegoDowngradeProtocol = 2;
        internal const byte DNegoAcceptedProtocolsMessage = 3;
        internal const byte DNegoMissingProtocols = 4;
        internal const byte DNegoEvictionDisallowed = 5;
        // Run discriminators:
        internal const byte DRunByeBye = 255;

        internal static readonly OutgoingMessageFactory _zeroFactory = MessageProtocol.ZeroProtocol.MessageFactory;

        /// <summary>
        /// ByeBye message is a signed message with the local identities.
        /// </summary>
        /// <param name="transport">The transport.</param>
        /// <param name="message">The message.</param>
        /// <returns>True if the message has been sent, false if Transport has been canceled.</returns>
        public static async ValueTask<bool> SendCreateByeByeMessageAsync( Transport transport, ByeByeMessage message )
        {
            Debug.Assert( transport.LocalKeys != null );
            Debug.Assert( message != null );
            using var m = CreateAndSignMessage( message, transport.LocalKeys.Identities );
            return await transport.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( ByeByeMessage message, IReadOnlyList<LocalIdentityKey> localIdentities )
            {
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );
                w.WriteByte( DRunByeBye );
                w.WriteString( message.Reason );
                w.WriteTimeSpan( message.ShutUp );
                w.Commit();
                WriteIdentityKeysAndSign( ref w, sequence, localIdentities );
                return builder.CreateMessage( sequence );
            }
        }

        public static ByeByeMessage? ReadByeByeMessage( IParallelLogger logger, Transport transport, IncomingMessage message )
        {
            Debug.Assert( transport.RemoteKeys != null );
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DRunByeBye );
            var m = new ByeByeMessage( r.ReadString(), r.ReadTimeSpan() );
            if( ReadIdentityKeysAndVerifySignatures( ref r,
                                                     transport.RemoteKeys.TrustedIdentity,
                                                     out var foundTrustedKey,
                                                     out var currentKeyData,
                                                     out var currentKey ) )
            {
                logger.Info( $"Received verified bye-bye message from '{transport.RemoteKeys.Party}': {m}" );
                transport.RemoteKeys.OnReadIdentityKeys( logger, foundTrustedKey, currentKeyData, currentKey );
                return m;
            }
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable bye-bye message from '{transport.RemoteKeys.Party}': {m}" );
            return null;
        }

    }
}
