using CK.AppIdentity.KeyManagement;
using CK.Core;
using Microsoft.Extensions.Hosting;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
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
            else if( _result.IsFaulted )
            {
                monitor.Warn( $"Error while handling incoming connection for '{_incoming.RemoteEndPointDescription}'. Destroying the transport.", _result.Exception );
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

            var initialResult = await HandleInitialMessageAsync( transportManager, incoming );
            if( !initialResult.HasValue ) return;

            var (initialMessage, remote, foundTrustKey) = initialResult.Value;

            // First, we handle invalid clock offset. This has been logged, but nothing has been
            // impacted (even the nonce has not been checked).
            if( !initialMessage.ValidClockOffset )
            {
                // Signals the InvalidClockOffset peering issue before sending the message.
                transportManager.InvalidClockOffset( initialMessage, remote, initialMessage.ClockOffset );
                // Replies the InvalidClockOffset. If this fails, we don't care.
                await ZeroProtocol.SendInvalidClockOffsetMessageAsync( transportManager.SystemClock, incoming, initialMessage.ClockOffset, initialMessage.Nonce );
                return;
            }
            // If the remote is not known, either intrinsically or because it has no trusted identity yet or our trusted identity key
            // doesn't appear in the message, signals this InitialMessage to the TransportManager: the incoming Remote may be accepted
            // later but for now, we reject the connection.
            if( remote == null || !foundTrustKey )
            {
                // Before awaking the TransportManager, we send the deny message:
                // If this is a bad remote guy that tries to timeout us, this will be cleanup by the heart beat:
                // no need for a cancellation token here.
                // Sends back the UnknownRemoteReplyMessage with the url to use to enlist this party.
                string? enlistUrl = transportManager.GetEnlistRemoteUrl( remote?.Party, initialMessage.DomainName );
                if( await ZeroProtocol.SendUnknownRemoteReplyMessageAsync( incoming, enlistUrl, initialMessage.Nonce, signatureVerificationFailed: false ) )
                {
                    // Only if the transport has not been condemned, tell the Transport manager about
                    // this potential new UnknownRemote party with the TransportFeature found (if any).
                    transportManager.UnknownOrUntrustedIncomingRemote( initialMessage, remote );
                }
                return;
            }
            // The remote is who it pretends to be.
            Debug.Assert( incoming.RemoteKeys != null );
            // If the remote is off, sends a bye-bye message.
            if( remote.IsOff )
            {
                await ZeroProtocol.SendOffRemoteMessageAsync( incoming, initialMessage.Nonce, TimeSpan.FromSeconds( 5 ) );
                return;
            }
            // Let's check the full protocol list we received by intersecting it
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

                transportManager.Logger.Error( $"Remote '{initialMessage.FullName}' at '{incoming.RemoteEndPointDescription}' "
                                              + $"misses support for {missingGroups.Count()} protocols:{Environment.NewLine}{texts}." );

                // If this message cannot be sent, we don't care.
                await ZeroProtocol.SendMissingProtocolsMessageAsync( incoming, initialMessage.Nonce, missing );
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
                    await ZeroProtocol.SendEvictionDisallowedMessageAsync( incoming, initialMessage.Nonce );
                    return;
                }
            }
            // We could check here that we cannot honor protocols of the other party but we let him decide:
            // we send the AcceptedMessage with the best protocols and it's on him. 
            var protocolMap = MessageProtocolMap.InternalGet( commonBest );
            // We now have no reason to reject it: we send the accept message: it this fails, it's
            // useless to put the connection manager at work.
            if( await ZeroProtocol.SendAcceptedProtocolsMessageAsync( transportManager.SystemClock, incoming, protocolMap, initialMessage.Nonce, initialMessage.ClockOffset ) )
            {
                // Wait for the final message, either:
                //  - A single "DNegoFinalFailureMessage" discriminator byte on failure.
                //  - A DNegoInitiatorSuccessMessage discriminator byte, the nonce, the remote's updated clock offset, the SHA512 hash (64 bytes) and
                //    the signtature (its length on one byte and up to 255 bytes).
                const int MaxInitiatorSuccessMessageLength = 1 + 8 + 8 + 64 + 1 + 255;
                using var finalInitiatorMessage = await incoming.ReadNextAsync( MaxInitiatorSuccessMessageLength );
                if( !finalInitiatorMessage.IsValid
                    || finalInitiatorMessage.Protocol != MessageProtocol.ZeroProtocol
                    || finalInitiatorMessage.Message.FirstSpan.Length == 0
                    || (finalInitiatorMessage.Message.FirstSpan[0] != ZeroProtocol.DNegoFinalFailureMessage
                        && finalInitiatorMessage.Message.FirstSpan[0] != ZeroProtocol.DNegoFinalSuccessMessage) )
                {
                    transportManager.Logger.Warn( $"Remote '{initialMessage.FullName}' at '{incoming.RemoteEndPointDescription}' replied an invalid final message." );
                }
                else if( finalInitiatorMessage.Message.FirstSpan[0] == ZeroProtocol.DNegoFinalFailureMessage )
                {
                    transportManager.Logger.Warn( $"Remote '{initialMessage.FullName}' at '{incoming.RemoteEndPointDescription}' replied with a failure message." );
                }
                else if( ZeroProtocol.TryReadFinalSuccessMessage( transportManager.Logger, finalInitiatorMessage, initialMessage.Nonce, remote, out var finalClockOffset ) )
                {
                    // We're almost done.
                    if( await ZeroProtocol.SendFinalSuccessMessageAsync( incoming, remote, initialMessage.Nonce, finalClockOffset ) )
                    {
                        // Final message is sent: we condemn the current transport if there is one.
                        var m = new ByeByeMessage( $"Evicted by instance '{initialMessage.InstanceId}' at '{initialMessage.RemoteEndPointDescription}'.",
                                                   TimeSpan.FromSeconds( 60 ) );
                        current?.CurrentTransport.SetSoftCondemned( m );
                        // By providing the party here instead of the transport feature, we'll check
                        // that the RemoteParty is not destroyed and the existence of the TransportFeature.
                        transportManager.NewValidTransport( remote.Party, incoming, protocolMap, finalClockOffset );
                    }
                    else
                    {
                        // Nonce check failed (this has been logged) or send has been canceled: let this transport die.
                    }
                }
                else
                {
                    // Either the nonce or the signature failed: let this transport die.
                }
            }
        }

        static async Task<(InitialMessage,TransportFeature?,bool)?> HandleInitialMessageAsync( TransportManager transportManager, Transport incoming )
        {
            Debug.Assert( incoming.Listener != null );
            InitialMessage? initialMessage = null;
            IncomingMessage? message = null;
            TransportFeature? remote = null;
            bool foundTrustKey = false;
            try
            {
                bool downgradedVersion = false;
                retry:
                message = await incoming.ReadNextAsync( maxMessageLength: InitialMessage.MaxLength );
                if( !message.IsValid || message == IncomingMessage.Empty || message == IncomingMessage.EmptyAck )
                {
                    transportManager.Logger.Warn( $"Empty or too long initial message received from '{incoming.RemoteEndPointDescription}'." );
                    return null;
                }
                // Let any exception while reading the initial message be a task error.
                initialMessage = TryParse( transportManager, incoming, message, out var otherVersion, out remote, out foundTrustKey );
                if( initialMessage == null )
                {
                    if( otherVersion == -1 )
                    {
                        // Nothing to do: this is not a remote!
                        transportManager.Logger.Warn( $"Initial message received from '{incoming.RemoteEndPointDescription}' miss the 'CK-AppId' prefix." );
                        return null;
                    }
                    if( otherVersion <= ZeroProtocol.CurrentVersion )
                    {
                        // We have read the first part of the message.
                        // If the initialMessage is null it is because its signature has failed the verification or the Nonce check failed (this has been logged).
                        // We send a null enlist url and don't lose any cpu/time/bandwidth to send our identity and sign the reply message.
                        await ZeroProtocol.SendUnknownRemoteReplyMessageAsync( incoming, null, 0, signatureVerificationFailed: true );
                        return null;
                    }
                    // The remote's version of the InitialMessage is greater than ours.
                    if( !downgradedVersion )
                    {
                        transportManager.Logger.Warn( $"Replying DowngradeProtocolReplyMessage to '{incoming.RemoteEndPointDescription}' (remote version is '{otherVersion}', our is '{ZeroProtocol.CurrentVersion}')." );
                        await ZeroProtocol.SendDowngradeProtocolReplyAsync( incoming );
                        // If the other can downgrade, it's cool. But do this only once.
                        downgradedVersion = true;
                        message.Release();
                        goto retry;
                    }
                    transportManager.Logger.Warn( $"Invalid InitialMessage version received from '{incoming.RemoteEndPointDescription}'." );
                    return default;
                }
            }
            finally
            {
                message?.Dispose();
            }
            return (initialMessage, remote, foundTrustKey);

            static InitialMessage? TryParse( TransportManager transportManager,
                                             Transport incoming,
                                             IncomingMessage message,
                                             out int otherVersion,
                                             out TransportFeature? remote,
                                             out bool foundTrustKey )
            {
                Debug.Assert( incoming.Listener != null, "We are listening." );
                var r = new FastByteReader( message.Message );
                if( !InitialMessage.TryParse( ref r,
                                              out otherVersion,
                                              out var instanceId,
                                              out var domainName,
                                              out var partyName,
                                              out var environmentName,
                                              out var fullName,
                                              out var protocols ) )
                {
                    remote = null;
                    foundTrustKey = false;
                    return null;
                }
                // Reads the nonce and computes the ClockOffset.
                var nonce = r.ReadUInt64();
                DateTime now = transportManager.SystemClock.UtcNow;
                var clockOffset = now - r.ReadDateTime();
                
                // The message seems fine. The first thing is to locate our remote across the registered listener's Parties.
                // Accessing the Parties is thread safe.
                // This COULD have been done by the TransportListener (lookup based on SSL certificates).
                remote = incoming.Listener.Parties.FirstOrDefault( p => p.Party.FullName.Path == fullName );
                Debug.Assert( remote == null || remote.IsListening );
                // We may know the remote (or not). If we do, we may have a trusted identity for it.
                var alreadyTrusted = remote?.RemoteKeys.TrustedIdentity;
                if( !ZeroProtocol.ReadIdentityKeysAndVerifySignatures( ref r, alreadyTrusted, out foundTrustKey, out var currentKeyData, out var currentKey ) )
                {
                    // The message's signature, regardless of whether we know the remote and have a trusted key for it, is NOT verified!
                    // This is a serious issue and we cannot do a lot here.
                    transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Unable to verify the signature's incoming message from '{fullName}'." );
                    return null;
                }
                // The message's signature is verified.
                // Before impacting anything we check the clock offset. A too large clock offset must not impact anything.
                bool validClockOffset = clockOffset > TimeSpan.Zero
                                            ? clockOffset < TransportFeature.MaxClockOffset
                                            : clockOffset > -TransportFeature.MaxClockOffset;

                // If we have a known remote and the clock offset is fine, we first check the nonce cache and
                // update its TrustedIdentity: AutoTrustKey may make us immediately accept the remote...
                if( remote != null && validClockOffset )
                {
                    // Nonce is checked only with a valid clock offset: this enables a rather small nonce cache.
                    // We update the nonce cache only if we already trust the remote (AutoTrustKey is not yet applied here).
                    if( !remote.RemoteKeys.CheckNonceCache( transportManager.Logger, now, nonce, foundTrustKey ) )
                    {
                        transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Invalid Nonce value received from '{fullName}'." );
                        return null;
                    }
                    // Important: The Transport MAY already know the RemoteKeys if the TransportListener was able to
                    //            open a SSL certified connection with already available SSL certificates but we don't care here: we handle the
                    //            initial message as if it was on a non confidential channel.
                    //            Moreover, we check here the work of the TransportListener and throws if a mismatch of keys happened: our source
                    //            of truth is the incoming message's FullName.
                    if( incoming.RemoteKeys == null )
                    {
                        incoming.SetKeys( remote.RemoteKeys );
                    }
                    else
                    {
                        if( incoming.RemoteKeys != remote.RemoteKeys )
                        {
                            Throw.InvalidOperationException( $"Buggy TransportListener: remote keys are not the right ones. " +
                                                             $"Expected keys for '{remote.RemoteKeys.Party}', got '{incoming.RemoteKeys.Party}.'" );
                        }
                    }
                    // If the AutoTrustKey does its job, we can accept the incoming connection immediately.
                    bool isalreadyTrusted = foundTrustKey;
                    foundTrustKey |= remote.RemoteKeys.OnReadIdentityKeys( transportManager.Logger, foundTrustKey, currentKeyData, currentKey );
                    // And if we did, then we add the nonce to the cache.
                    if( !isalreadyTrusted && foundTrustKey )
                    {
                        remote.RemoteKeys.AddNonce( transportManager.Logger, now, nonce );
                    }
                }
                return new InitialMessage( incoming.Listener.EndPointDescription,
                                           incoming.RemoteEndPointDescription,
                                           otherVersion,
                                           instanceId,
                                           domainName,
                                           partyName,
                                           environmentName,
                                           fullName,
                                           protocols,
                                           nonce,
                                           validClockOffset,
                                           clockOffset,
                                           currentKeyData );
            }
        }
    }
}
