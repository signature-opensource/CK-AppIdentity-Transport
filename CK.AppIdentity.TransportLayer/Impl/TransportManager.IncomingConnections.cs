using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    sealed partial class TransportManager
    {
        /// <summary>
        /// The UnknownRemoteReply is one byte "0" message (2 bytes on the wire).
        /// </summary>
        public static TransportMessage UnknownRemoteReplyMessage = TransportMessageFactory.CreateStatic( bytes =>
        {
            bytes.GetSpan( 1 )[0] = 0;
            bytes.Advance( 1 );
        } );

        /// <summary>
        /// The AcceptedRemoteReplyMessage is one byte "1" message (2 bytes on the wire).
        /// </summary>
        public static TransportMessage AcceptedRemoteReplyMessage = TransportMessageFactory.CreateStatic( bytes =>
        {
            bytes.GetSpan( 1 )[0] = 1;
            bytes.Advance( 1 );
        } );


        /// <summary>
        /// This task is launched on a new Transport and added into the _backgroundTaskList list,
        /// it is executed in the background and its result is an error string or may perfectly be an exception (the Task is faulted).
        /// The connection manager's heart beat checks this list for successful or faulty results or too long execution: this
        /// enables no timeout and no exception handling stuff.
        /// </summary>
        /// <param name="t">The brand new, not yet validated Transport.</param>
        /// <returns>A task that tries to validate the Transport.</returns>
        async Task<string?> HandleIncomingTransportStartAsync( Transport t )
        {
            Debug.Assert( t.Listener != null );
            var m = await t.ReadNextAsync( maxMessageLength: 2048 );
            if( !m.IsValid ) return "Invalid message received.";
            var initialMessage = new InitialMessage( t.Listener.EndPointDescription, m );
            // Accessing the Parties is thread safe.
            var remote = t.Listener.Parties.FirstOrDefault( p => p.FullName.Path == initialMessage.FullName );
            // If the remote is not known, signals this InitialMessage to the ConnectionManager:
            // The incoming Remote may be accepted later but for now, we reject the connection.
            if( remote == null )
            {
                // Before awaking the ConnectionManager, we send the deny message: it this fails.
                // If this is a bad remote guy that tries to timeout us, this will be cleanup by the heart beat:
                // no need for a cancellation token here.
                await t.SendAsync( UnknownRemoteReplyMessage );
                PushTypedJob( initialMessage );
                return "UnknownRemote";
            }
            // We know the remote full name. We check its signature.
            // TODO.

            // This Transport is now valid. The connection manager has no reason to reject it:
            // either this Transport will be the first one of the Remote or replace the current one
            // or be part of a CompositeTransport, the connection manager is in charge of these choices.
            // We can set a success (null is no error) on this task, but before that we send the
            // accept message: it this fails, it's useless to put the connection manager at work.
            await t.SendAsync( AcceptedRemoteReplyMessage );
            PushTypedJob( new IncomingAcceptedTransportJob( remote, t ) );
            return null;
        }

        async ValueTask HandleUnknownIncomingRemote( IActivityMonitor monitor, UnknownIncomingRemoteJob u )
        {
            _waitingList.Add( u.InitialMessage );
            await _waitingListChanged.SafeRaiseAsync( monitor, u.InitialMessage );
        }

        ValueTask HandleIncomingAcceptedTransport( IActivityMonitor monitor, IncomingAcceptedTransportJob remoteTransport )
        {
            var channel = remoteTransport.Remote.GetRequiredFeature<TransportFeature>();
            channel.OnNewTransport( monitor, remoteTransport.Transport );
            return default;
        }
    }
}
