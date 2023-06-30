using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Diagnostics;
using System.Reflection;
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
        Transport? _incoming;
        Task? _result;

        public override void OnDestroy( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _incoming != null && _result != null );
            transportManager.KillTransport( _incoming );
        }

        public override void Check( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _incoming != null && _result != null );
            if( !_result.IsCompleted  )
            {
                monitor.Warn( $"Incoming connection timeout for '{_incoming.RemoteEndPointDescription}'. Destroying the transport." );
                transportManager.KillTransport( _incoming );
            }
        }

        public override void Reset()
        {
            _incoming = null;
            _result = null;
        }

        public void Setup( TransportManager transportManager, Transport incoming )
        {
            Debug.Assert( incoming.Listener != null );
            _incoming = incoming;
            _result = Task.Run( () => RunAsync( transportManager, incoming ) );
        }

        static async Task RunAsync( TransportManager transportManager, Transport incoming )
        {
            Debug.Assert( incoming?.Listener != null );

            InitialMessage? initialMessage = await HandleInitialMessageAsync( transportManager, incoming );
            if( initialMessage == null ) return;

            // Accessing the Parties is thread safe.
            TransportFeature? remote = incoming.Listener.Parties.FirstOrDefault( p => p.Party.FullName.Path == initialMessage.IncomingFullName );
            Debug.Assert( remote == null || remote.IsListening );
            // If the remote is not known, either intrinsically or because it has no trusted identity yet, signals this InitialMessage
            // to the TransportManager: the incoming Remote may be accepted later but for now, we reject the connection.
            // Note: if remote is not null, we are listening and hence we have a non null RemoteKeys. Unfortunately, null propagation
            //       analysis fails here.
            var trustedIdentity = remote?.RemoteKeys!.TrustedIdentity;
            if( trustedIdentity == null || !initialMessage.RemoteIdentities.Any( i => i.Equals( trustedIdentity ) ) )
            {
                // Before awaking the TransportManager, we send the deny message:
                // If this is a bad remote guy that tries to timeout us, this will be cleanup by the heart beat:
                // no need for a cancellation token here.
                // Sends back the UnknownRemoteReplyMessage with the url to use to enlist this party if it is configured.
                // TODO:
                string? userAcceptUri = null; // _transportManager.ApplicationIdentityAgent.GetAcceptUriFor( initialMessage.FullName );
                if( await ZeroProtocol.SendUnknownRemoteReplyMessageAsync( incoming, userAcceptUri ) )
                {
                    // if the transport has not been condemned, tell the Transport manager about
                    // this potential new UnknownRemote party with the trusted identity (if any) considered at the
                    // time of the decision.
                    transportManager.UnknownIncomingRemote( initialMessage, trustedIdentity );
                }
                return;
            }
            // We know the remote full name and we trust one of its public keys: it is time to verify the message signatures.
            // The message is signed by each of its identities but it would be useless and costly to verify each of them (we will have to
            // instantiate a ECDsa for each of the RemotePublicKeyData). We just have to check the signature against our trustedIdentity
            // that already has a ECDsa up and running.


            // If the remote is off, sends a bye-bye message.
            if( remote.IsOff )
            {
                await ZeroProtocol.SendCreateByeByeMessageAsync( incoming, new ByeByeMessage( "IsOff", TimeSpan.FromSeconds( 2 ) ) );
                return;
            }
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

                transportManager.Logger.Error( $"Remote '{initialMessage.IncomingFullName}' at '{incoming.RemoteEndPointDescription}' "
                                              + $"misses support for {missingGroups.Count()} protocols:{Environment.NewLine}{texts}." );

                // If this message cannot be sent, we don't care.
                await ZeroProtocol.SendMissingProtocolsMessageAsync( incoming, missing );
                return;
            }
            // This Transport is now valid (up to us).
            // But our remote may not accept "eviction". 
            var current = remote.TransportController;
            if( current != null && !current.CurrentTransport.IsCondemned )
            {
                if( remote.DisallowEviction )
                {
                    transportManager.Logger.Warn( $"Remote '{remote.Party.FullName}' while already connected to '{current.CurrentTransport}'. DisallowEviction is true: sending EvictionDisallowedMessage and closing." );
                    // If this message cannot be sent, we don't care.
                    await ZeroProtocol.SendEvictionDisallowedMessageAsync( incoming );
                    return;
                }
            }
            // We could check here that we cannot honor protocols of the other party but we let him decide:
            // we send the AcceptedMessage with the best protocols and it's on him. 
            var protocolMap = MessageProtocolMap.InternalGet( commonBest );
            // We now have no reason to reject it: we send the accept message: it this fails, it's
            // useless to put the connection manager at work.
            if( await ZeroProtocol.SendAcceptedProtocolsMessageAsync( remote, incoming, protocolMap ) )
            {
                // Wait for the final message.
                // It must be a single "1" byte.
                using var finalMessage = await incoming.ReadNextAsync( maxMessageLength: 1 );
                if( finalMessage.IsValid && finalMessage.Protocol == MessageProtocol.ZeroProtocol && finalMessage.Message.FirstSpan[0] == 1 )
                {
                    // Final message is received: we condemn the current transport if there is one.
                    var m = new ByeByeMessage( $"Evicted by instance '{initialMessage.InstanceId}' at '{initialMessage.RemoteEndPointDescription}'.", TimeSpan.FromSeconds( 5 ) );
                    current?.CurrentTransport.SetSoftCondemned( m );
                    // By providing the party here instead of the transport feature, we'll check
                    // that the RemoteParty is not destroyed and the existence of the TransportFeature.
                    transportManager.NewValidTransport( remote.Party, incoming, protocolMap );
                }
                else
                {
                    transportManager.Logger.Warn( $"Remote '{initialMessage.IncomingFullName}' at '{incoming.RemoteEndPointDescription}' didn't confirm." );
                }
            }
        }

        static async Task<InitialMessage?> HandleInitialMessageAsync( TransportManager transportManager, Transport incoming )
        {
            Debug.Assert( incoming?.Listener != null );
            InitialMessage? initialMessage;

            TransportMessage? message = null;
            try
            {
                bool downgradedVersion = false;
                retry:
                message = await incoming.ReadNextAsync( maxMessageLength: InitialMessage.MaxLength );
                if( !message.IsValid || message == TransportMessage.Empty || message == TransportMessage.EmptyAck )
                {
                    transportManager.Logger.Warn( $"Empty or too long initial message received from '{incoming.RemoteEndPointDescription}'." );
                    return null;
                }
                // Let any exception while reading the initial message be a task error.
                bool success = InitialMessage.TryParse( incoming.Listener.EndPointDescription, incoming.RemoteEndPointDescription, message, out initialMessage, out var otherVersion );
                if( !success )
                {
                    if( otherVersion == -1 )
                    {
                        // Nothing to do: this is not a remote!
                        transportManager.Logger.Warn( $"Initial message received from '{incoming.RemoteEndPointDescription}' miss the 'CK-AppId' prefix." );
                        return null;
                    }
                    // The remote's version of the InitialMessage is greater than ours.
                    if( !downgradedVersion )
                    {
                        transportManager.Logger.Warn( $"Replying DowngradeProtocolReplyMessage to '{incoming.RemoteEndPointDescription}' (remote version is '{otherVersion}', our is '{ZeroProtocol.CurrentVersion}')." );
                        await ZeroProtocol.SendDowngradeProtocolReplyAsync( incoming );
                        // If the other can downgrade, it's cool. But do this only once.
                        downgradedVersion = true;
                        goto retry;
                    }
                    transportManager.Logger.Warn( $"Invalid InitialMessage version received from '{incoming.RemoteEndPointDescription}'." );
                    return null;
                }
            }
            finally
            {
                message?.Dispose();
            }
            return initialMessage;
        }
    }
}
