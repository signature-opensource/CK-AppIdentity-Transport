using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// This one shot BackTask handles new <see cref="Transport"/> from a <see cref="TransportListener"/>.
    /// The protocol initialization is implemented as a BackTask since we have no clue of the actual remote
    /// identity that tries to connect: all the dirty work can be "observed from the outer" and the task
    /// totally forgotten if needed. This fully isolate the listener that can never be blocked.
    /// </summary>
    sealed class IncomingConnectionBackTask : BackTask
    {
        TransportManager? _transportManager;
        Transport? _incoming;
        Task? _result;

        public override void Check( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _incoming != null && _result != null );
            if( !_result.IsCompleted  )
            {
                monitor.Warn( $"Incoming connection handling for '{_incoming.RemoteEndPointDescription}' timed out. Destroying the transport." );
            }
            transportManager.CondemnTransport( _incoming );
        }

        public override void Reset()
        {
            _transportManager = null;
            _incoming = null;
            _result = null;
        }

        public void Setup( TransportManager transportManager, Transport incoming )
        {
            Debug.Assert( transportManager != null && incoming.Listener != null );
            _transportManager = transportManager;
            _incoming = incoming;
            _result = Task.Run( RunAsync );
        }

        async Task RunAsync()
        {
            Debug.Assert( _transportManager != null && _incoming != null && _incoming.Listener != null );

            InitialMessage? initialMessage = await HandleInitialMessageAsync();
            if( initialMessage == null ) return;

            // Accessing the Parties is thread safe.
            var remote = _incoming.Listener.Parties.FirstOrDefault( p => p.FullName.Path == initialMessage.FullName );
            // If the remote is not known, signals this InitialMessage to the TransportManager:
            // The incoming Remote may be accepted later but for now, we reject the connection.
            if( remote == null )
            {
                // Before awaking the TransportManager, we send the deny message:
                // If this is a bad remote guy that tries to timeout us, this will be cleanup by the heart beat:
                // no need for a cancellation token here.
                await _incoming.SendAsync( TransportManager.UnknownRemoteReplyMessage );
                // Tell the Transport manager about this potential new remote party.
                _transportManager.UnknownIncomingRemote( initialMessage );
                return;
            }
            // We know the remote full name. We check the signature.
            // TODO.

            // This Transport is now valid. The connection manager has no reason to reject it:
            // either this Transport will be the first one of the Remote or replace the current one
            // or be part of a CompositeTransport, the connection manager is in charge of these choices.
            // We can set a success (null is no error) on this task, but before that we send the
            // accept message: it this fails, it's useless to put the connection manager at work.
            using var accepted = _transportManager.MessageSendingFactory.Create( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteByte( 2 );
                w.Commit();
            } );
            await _incoming.SendAsync( accepted );
            // Wait for the ACK (currently the empty message).
            using var ack = await _incoming.ReadNextAsync();
            {
                if( ack != TransportMessage.Empty )
                {
                    _transportManager.Logger.Warn( $"Remote '{initialMessage.FullName}' at '{_incoming.RemoteEndPointDescription}' didn't confirm." );
                    return;
                }
            }
            _transportManager.IncomingAcceptedTransport( remote, _incoming );
        }

        async Task<InitialMessage?> HandleInitialMessageAsync()
        {
            Debug.Assert( _transportManager != null && _incoming != null && _incoming.Listener != null );
            InitialMessage? initialMessage;
            bool downgradedVersion = false;
            retry:
            TransportMessage m = await _incoming.ReadNextAsync( maxMessageLength: 2048 );
            if( !m.IsValid || m == TransportMessage.Empty )
            {
                _transportManager.Logger.Warn( $"Empty or too long initial message received from '{_incoming.RemoteEndPointDescription}'." );
                return null;
            }
            try
            {
                // Let any exception while reading the initial message be a task error.
                initialMessage = InitialMessage.Parse( _incoming.Listener.EndPointDescription, m );
                if( initialMessage == null )
                {
                    // The remote's version of the InitialMessage is greater than ours.
                    if( !downgradedVersion )
                    {
                        _transportManager.Logger.Warn( $"Replying DowngradeProtocolReplyMessage to '{_incoming.RemoteEndPointDescription}'." );
                        await _incoming.SendAsync( TransportManager.DowngradeProtocolReplyMessage );
                        goto retry;
                    }
                    _transportManager.Logger.Warn( $"Invalid InitialMessage version received from '{_incoming.RemoteEndPointDescription}'." );
                    return null;
                }
            }
            finally
            {
                m.Dispose();
            }
            return initialMessage;
        }
    }
}
