using CK.Core;
using System.Diagnostics;
using System.Reflection.Emit;
using System.Text;

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

        public override void OnDestroy( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _incoming != null && _result != null );
            transportManager.CondemnTransport( _incoming );
        }

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
            TransportLayerFeature? remote = _incoming.Listener.Parties.FirstOrDefault( p => p.Party.FullName.Path == initialMessage.FullName );
            // If the remote is not known, signals this InitialMessage to the TransportManager:
            // The incoming Remote may be accepted later but for now, we reject the connection.
            if( remote == null )
            {
                // Before awaking the TransportManager, we send the deny message:
                // If this is a bad remote guy that tries to timeout us, this will be cleanup by the heart beat:
                // no need for a cancellation token here.
                // Sends back the UnknownRemoteReplyMessage with the url to use to enlist this party if it is configured.
                // TODO:
                string? userAcceptUri = null; // _transportManager.ApplicationIdentityAgent.GetAcceptUriFor( initialMessage.FullName );
                await ZeroProtocol.SendUnknownRemoteReplyMessageAsync( _incoming, userAcceptUri );
                // Tell the Transport manager about this potential new IUnknownRemote party.
                _transportManager.UnknownIncomingRemote( initialMessage );
                return;
            }
            // We know the remote full name. We first verify the signature.
            // TODO.

            // The remote is who it pretends to be, let's check the full protocol list we received by intersecting it
            // with our declared protocol (and selecting the highest common version for each of them).
            MessageProtocol[] commonBest = remote.RegisteredProtocols.IntersectBy( initialMessage.AvailableProtocols, p => p.FullName )
                                                                     .GroupBy( p => p.Name )
                                                                     .Select( g => g.MaxBy( g => g.Version ) )
                                                                     .ToArray()!;
            // If the protocols from the other side don't satisfy us, we send the
            // MissingProtocolsMessage and let the caller close the connection (if it can do it quick enough).
            if( commonBest.Length != remote.BestRegisteredProtocols.Count )
            {
                Debug.Assert( commonBest.Length < remote.BestRegisteredProtocols.Count );
                var missing = remote.BestRegisteredProtocols.Where( p => !commonBest.Any( c => c.Name == p.Name ) )
                                                            .SelectMany( m => remote.RegisteredProtocols.Where( r => r.Name == m.Name ) )
                                                            .ToList();
                var missingGroups = missing.GroupBy( m => m.Name );
                var texts = missingGroups.Select( g => $"'{g.Key}': '{g.Select( p => p.FullName ).Concatenate( "', '" )}')" )
                                         .Concatenate( Environment.NewLine );

                _transportManager.Logger.Error( $"Remote '{initialMessage.FullName}' at '{_incoming.RemoteEndPointDescription}' "
                                              + $"misses support for '{missingGroups.Count()}' protocols:{Environment.NewLine}{texts}." );

                await ZeroProtocol.SendMissingProtocolsMessageAsync( _incoming, missing );
                return;
            }
            // We could check here that we cannot honor protocols of the other party but we let him decide:
            // we send the AcceptedMessage with the best protocols and it's on him. 
            var protocolMap = MessageProtocolMap.InternalGet( commonBest );
            // This Transport is now valid (up to us). The connection manager has no reason to reject it:
            // either this Transport will be the first one of the Remote or replace the current one
            // or be part of a CompositeTransport, the connection manager and the TransprtFeateure are in
            // charge of these choices.
            // We send the accept message: it this fails, it's useless to put the connection manager at work.
            await ZeroProtocol.SendAcceptedMessageAsync( remote, _incoming, protocolMap );
            // Wait for the final message.
            // It must be a single "1" byte.
            using var finalMessage = await _incoming.ReadNextAsync( maxMessageLength: 1 );
            if( !finalMessage.IsValid || finalMessage.Protocol != MessageProtocol.ZeroProtocol || finalMessage.Message.FirstSpan[0] != 1 )
            {
                _transportManager.Logger.Warn( $"Remote '{initialMessage.FullName}' at '{_incoming.RemoteEndPointDescription}' didn't confirm." );
                return;
            }
            // By providing the party here instead of the transport feature, we'll check
            // that the RemoteParty is not destroyed and the existence of the TransportFeature.
            _transportManager.NewValidTransport( remote.Party, _incoming, protocolMap );
        }

        async Task<InitialMessage?> HandleInitialMessageAsync()
        {
            Debug.Assert( _transportManager != null && _incoming != null && _incoming.Listener != null );
            InitialMessage? initialMessage;

            TransportMessage? incoming = null;
            try
            {
                bool downgradedVersion = false;
                retry:
                incoming = await _incoming.ReadNextAsync( maxMessageLength: InitialMessage.MaxLength );
                if( !incoming.IsValid || incoming == TransportMessage.Empty )
                {
                    _transportManager.Logger.Warn( $"Empty or too long initial message received from '{_incoming.RemoteEndPointDescription}'." );
                    return null;
                }
                // Let any exception while reading the initial message be a task error.
                bool success = InitialMessage.TryParse( _incoming.Listener.EndPointDescription, incoming, out initialMessage, out var otherVersion );
                if( !success )
                {
                    if( otherVersion == -1 )
                    {
                        // Nothing to do: this is not a remote!
                        _transportManager.Logger.Warn( $"Initial message received from '{_incoming.RemoteEndPointDescription}' miss the 'CK-AppId' prefix." );
                        return null;
                    }
                    // The remote's version of the InitialMessage is greater than ours.
                    if( !downgradedVersion )
                    {
                        _transportManager.Logger.Warn( $"Replying DowngradeProtocolReplyMessage to '{_incoming.RemoteEndPointDescription}' (remote version is '{otherVersion}', our is '{ZeroProtocol.CurrentVersion}')." );
                        await ZeroProtocol.SendDowngradeProtocolReplyAsync( _incoming );
                        // If the other can downgrade, it's cool. But do this only once.
                        downgradedVersion = true;
                        goto retry;
                    }
                    _transportManager.Logger.Warn( $"Invalid InitialMessage version received from '{_incoming.RemoteEndPointDescription}'." );
                    return null;
                }
            }
            finally
            {
                incoming?.Dispose();
            }
            return initialMessage;
        }
    }
}
