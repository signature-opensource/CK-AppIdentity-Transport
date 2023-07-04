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

        public static async ValueTask<bool> SendCreateByeByeMessageAsync( Transport transport, ByeByeMessage message )
        {
            Debug.Assert( message != null );
            var m = _zeroFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DRunByeBye );
                w.WriteString( message.Reason );
                w.WriteTimeSpan( message.ShutUp );
                w.Commit();
            } );
            bool r = await transport.SendAsync( 0, m ).ConfigureAwait( false );
            m.Release();
            return r;
        }

        public static ByeByeMessage ReadByeByeMessage( IncomingMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DRunByeBye );
            return new ByeByeMessage( r.ReadString(), r.ReadTimeSpan() );
        }

    }
}
