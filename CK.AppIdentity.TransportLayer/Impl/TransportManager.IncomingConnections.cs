using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    sealed partial class TransportManager
    {
        /// <summary>
        /// The UnknownRemoteReply is a 2 bytes "00" message (3 bytes on the wire).
        /// First "0" is the 0 protocol.
        /// Second "0" is the rejection.
        /// </summary>
        internal static TransportMessage UnknownRemoteReplyMessage = TransportMessageFactory.CreateStatic( /*0, */bytes =>
        {
            var m = bytes.GetSpan( 2 );
            m[0] = 0;
            m[1] = 0;
            bytes.Advance( 2 );
        } );

        /// <summary>
        /// First "0" is the 0 protocol.
        /// Second "1" is the bad version indicator.
        /// Then comes our version.
        /// </summary>
        internal static TransportMessage DowngradeProtocolReplyMessage = TransportMessageFactory.CreateStatic( /*0, */bytes =>
        {
            var w = new FastByteWriter( bytes );
            w.WriteByte( 1 );
            w.WriteSmallUInt32( InitialMessage.CurrentVersion );
            w.Commit();
        } );

        /// <summary>
        /// The AcceptedRemoteReplyMessage is one byte "1" message (2 bytes on the wire).
        /// </summary>
        public static TransportMessage AcceptedRemoteReplyMessage = TransportMessageFactory.CreateStatic( bytes =>
        {
            bytes.GetSpan( 1 )[0] = 1;
            bytes.Advance( 1 );
        } );

        async ValueTask HandleUnknownIncomingRemote( IActivityMonitor monitor, InitialMessage initialMessage )
        {
            _waitingList.Add( initialMessage );
            await _waitingListChanged.SafeRaiseAsync( monitor, initialMessage );
        }

        ValueTask HandleIncomingAcceptedTransport( IActivityMonitor monitor, IncomingAcceptedTransportJob remoteTransport )
        {
            var channel = remoteTransport.Remote.GetRequiredFeature<TransportFeature>();
            channel.OnNewTransport( monitor, remoteTransport.Transport );
            return default;
        }
    }
}
