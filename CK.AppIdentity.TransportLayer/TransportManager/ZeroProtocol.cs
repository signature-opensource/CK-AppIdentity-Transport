using System.Diagnostics;

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

        public static TransportMessage CreateByeByeMessage( ByeByeMessage m )
        {
            Debug.Assert( m != null );
            return OutgoingMessageFactory.ZeroProtocol.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( DRunByeBye );
                w.WriteString( m.Reason );
                w.WriteTimeSpan( m.ShutUp );
                w.Commit();
            } );
        }

        public static ByeByeMessage ReadByeByeMessage( TransportMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DRunByeBye );
            return new ByeByeMessage( r.ReadString(), r.ReadTimeSpan() );
        }

    }
}
