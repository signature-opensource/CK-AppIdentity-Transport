using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

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
        DateTime _initializeTime;

        public override void OnDestroy( IActivityMonitor monitor, TransportManager transportManager )
        {
            Throw.DebugAssert( _incoming != null && _result != null );
            transportManager.KillTransport( _incoming );
        }

        public override void Check( IActivityMonitor monitor, TransportManager transportManager )
        {
            Throw.DebugAssert( _incoming != null && _result != null );
            if( !_result.IsCompleted )
            {
                var delta = DateTime.UtcNow - _initializeTime;
                if( delta > TimeSpan.FromMilliseconds( TransportManager.NegotiationTimeout ) )
                {
                    monitor.Warn( $"Incoming connection timeout ({(int)delta.TotalMilliseconds} ms) for '{_incoming}'. Destroying the transport." );
                    transportManager.KillTransport( _incoming );
                }
            }
            else if( _result.IsFaulted )
            {
                monitor.Warn( $"Error while handling incoming connection for '{_incoming}'. Destroying the transport.", _result.Exception );
                transportManager.KillTransport( _incoming );
            }
            else
            {
                monitor.Debug( $"IncomingConnectionBackTask #{GetHashCode()} Done (Transport: '{_incoming}')." );
            }
        }

        public override void Reset()
        {
            _incoming = null;
            _result = null;
        }

        public void OnInitialize( TransportManager transportManager, Transport incoming )
        {
            Throw.DebugAssert( incoming.Listener != null );
            _incoming = incoming;
            _initializeTime = DateTime.UtcNow;
            _result = Task.Run( () => RunAsync( transportManager, incoming ) );
            // Take no risk: integer division (to the floor).
            Throw.DebugAssert( "1 second is the default and the max and it cannot be 0.",
                               transportManager.SystemClock.HeatBeatPeriod <= 1000 && transportManager.SystemClock.HeatBeatPeriod >= 20 );
            Retry( 1000 / transportManager.SystemClock.HeatBeatPeriod );
        }

        static async Task RunAsync( TransportManager transportManager, Transport incoming )
        {
            var success = await DoRunAsync( transportManager, incoming );
            if( !success )
            {
                transportManager.KillTransport( incoming );
            }
        }

        static async Task<bool> DoRunAsync( TransportManager transportManager, Transport incoming )
        {
            Throw.DebugAssert( incoming?.Listener != null );

            var initialResult = await HandleInitialMessageAsync( transportManager, incoming ).ConfigureAwait( false );
            if( !initialResult.HasValue ) return false;

            var (initialMessage, remote, foundTrustKey) = initialResult.Value;

            // First, we handle invalid clock offset. This has been logged, but nothing has been
            // impacted (even the nonce has not been checked: this enables to keep a small nonce cache).
            if( !initialMessage.IsValidClockOffset )
            {
                // Signals the InvalidClockOffset peering issue before sending the message.
                transportManager.OnInvalidClockOffsetIssue( initialMessage, remote, initialMessage.ClockOffset );
                // Replies the InvalidClockOffset. If this fails, we don't care.
                await ZeroProtocol.SendInvalidClockOffsetMessageAsync( incoming, initialMessage.ClockOffset, initialMessage.Nonce ).ConfigureAwait( false );
                return false;
            }

            // This handles null or untrusted remote and the RemoteTrustInfo.
            // - When the remote is null (because it has not been found in this incoming.Listener.Parties), we try to find him among
            //   the ApplicationIdentityService.AllRemotes: the issue can then be "IncomingUnknwon", "IncomingDisallowedTransport",
            //   "InitiatorConflict" or "IncomingUnsupportedTransport".
            //   => We resolve the existingParty and updates the remote here so that:
            //      - We can always sign the message except for "IncomingUnknwon" and "IncomingDisallowedTransport".
            //      - the PeeringIssue can have its TransportFeature if possible.
            // - Based on foundTrustKey and initialMessage.RemoteTrustInfo (we can predict that the remote will not be able to trust us),
            //   the issue can be "RequiresLocalApproval" (foundTrustKey is false), "RequiresRemoteApproval" or "RequiresBothApproval".
            // - Otherwise the issue is "None".
            PeeringIssueKind issue = DetectConfigurationOrTrustIssue( transportManager,
                                                                      incoming,
                                                                      initialMessage,
                                                                      ref remote,
                                                                      foundTrustKey,
                                                                      out var existingParty );

            if( issue != PeeringIssueKind.None )
            {
                await HandleConfigurationOrTrustIssueAsync( transportManager, incoming, initialMessage, remote, issue, existingParty ).ConfigureAwait( false );
                return false;
            }
            Throw.DebugAssert( "We have a trusted remote.", remote != null && foundTrustKey );

            // Before handling the protocols, if our transport is off, sends the DNegoOffRemote message.
            var offMessage = remote.SwitchOffMessage;
            if( offMessage != null )
            {
                await ZeroProtocol.SendOffRemoteMessageAsync( incoming, initialMessage.Nonce, initialMessage.ClockOffset, offMessage ).ConfigureAwait( false );
                return false;
            }

            // Checks the missing protocols on both sides.
            var commonBest = await HandleProtocolsAsync( transportManager, initialMessage, incoming, remote );
            if( commonBest == null ) return false;

            // This Transport is now valid (up to us).
            // But our remote may not accept "eviction". 
            var current = remote.TransportController;
            if( current != null && !current.CurrentTransport.IsCondemned )
            {
                if( remote.DisallowEviction )
                {
                    transportManager.Logger.Warn( $"Incoming call from remote '{remote.Party.FullName}' while already connected to '{current.CurrentTransport}'. " +
                                                  $"DisallowEviction is true: sending EvictionDisallowedMessage and closing." );
                    // If this message cannot be sent, we don't care.
                    await ZeroProtocol.SendEvictionDisallowedMessageAsync( incoming, initialMessage.Nonce ).ConfigureAwait( false );
                    return false;
                }
            }
            // The protocol map is not really needed but it asserts the validity of the protocol list. 
            var protocolMap = MessageProtocolMap.InternalGet( commonBest );

            // We now have no reason to reject it: we send the accept message: it this fails, it's
            // useless to put the connection manager at work.
            if( await ZeroProtocol.SendAcceptedProtocolsMessageAsync( transportManager.SystemClock,
                                                                      incoming,
                                                                      protocolMap,
                                                                      initialMessage.Nonce,
                                                                      initialMessage.ClockOffset ).ConfigureAwait( false ) )
            {
                // Wait for the final message, either:
                //  - A single "DNegoFinalFailureMessage" discriminator byte on failure.
                //  - A DNegoFinalSuccessMessage discriminator byte, the nonce, the remote's updated clock offset, the SHA512 hash (64 bytes) and
                //    the signature (its length on one byte and up to 255 bytes).
                const int MaxInitiatorSuccessMessageLength = 1 + 8 + 8 + 64 + 1 + 255;
                using var finalInitiatorMessage = await incoming.ReadNextAsync( MaxInitiatorSuccessMessageLength ).ConfigureAwait( false );
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
                    // Final message is received: the current transport (if any) will be evicted.
                    var m = new GoodbyeMessage.Evicted( initialMessage.RemoteEndPointDescription, initialMessage.InstanceId );
                    // By providing the party here instead of the transport feature, we'll check
                    // that the RemoteParty is not destroyed and the existence of the TransportFeature.
                    transportManager.NewValidTransport( remote.Party, incoming, protocolMap, finalClockOffset, m );
                    return true;
                }
                else
                {
                    // Either the nonce or the signature failed: let this transport die.
                }
            }
            return false;
        }

        static async Task<(InitialMessage,TransportFeature?,bool)?> HandleInitialMessageAsync( TransportManager transportManager, Transport incoming )
        {
            Throw.DebugAssert( incoming.Listener != null );
            InitialMessage? initialMessage = null;
            IncomingMessage? message = null;
            TransportFeature? remote = null;
            bool foundTrustKey = false;
            try
            {
                bool downgradedVersion = false;
                retry:
                message = await incoming.ReadNextAsync( maxMessageLength: InitialMessage.MaxLength ).ConfigureAwait( false );
                if( !message.IsValid || message == IncomingMessage.Empty || message == IncomingMessage.EmptyAck )
                {
                    if( message == IncomingMessage.Canceled )
                    {
                        transportManager.Logger.Debug( $"Canceled read for '{incoming.RemoteEndPointDescription}'." );
                    }
                    else
                    {
                        transportManager.Logger.Warn( $"Empty or too long initial message received from '{incoming.RemoteEndPointDescription}'." );
                    }
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
                        // We send a one byte message and don't lose any cpu/time/bandwidth to send our identity and sign the reply message.
                        await ZeroProtocol.SendFinalFailureMessageAsync( incoming ).ConfigureAwait( false );
                        return null;
                    }
                    // The remote's version of the InitialMessage is greater than ours.
                    if( !downgradedVersion )
                    {
                        transportManager.Logger.Warn( $"Replying DowngradeProtocolReplyMessage to '{incoming.RemoteEndPointDescription}' (remote version is '{otherVersion}', our is '{ZeroProtocol.CurrentVersion}')." );
                        await ZeroProtocol.SendDowngradeProtocolReplyAsync( incoming ).ConfigureAwait( false );
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
                Throw.DebugAssert( "We are listening.", incoming.Listener != null );
                var r = new FastByteReader( message.Message );
                if( !InitialMessage.TryParse( ref r,
                                              out otherVersion,
                                              out var instanceId,
                                              out var domainName,
                                              out var partyName,
                                              out var environmentName,
                                              out var fullName,
                                              out var protocols,
                                              out var expectedCommonProtocolCount,
                                              out var canAutoTrust,
                                              out var supposedIdentity) )
                {
                    remote = null;
                    foundTrustKey = false;
                    return null;
                }
                // Reads the timed nonce.
                var timedNonce = new TimedNonce( r.ReadDateTime(), r.ReadUInt64() );
                
                // The message seems fine. The first thing is to locate our remote across the registered listener's Parties.
                // Accessing the Parties is thread safe.
                // This COULD have been done by the TransportListener (lookup based on SSL certificates).
                remote = incoming.Listener.Parties.FirstOrDefault( p => p.Party.FullName.Path == fullName );
                Throw.DebugAssert( remote == null || remote.IsListening );

                // We may know the remote (or not). If we do, we may have a trusted identity for it.
                var alreadyTrusted = remote?.RemoteKeys.TrustedIdentity;
                if( !ZeroProtocol.ReadIdentityKeysAndVerifySignatures( ref r, alreadyTrusted, out foundTrustKey, out var currentKeyData, out var currentKey ) )
                {
                    // The message's signature, regardless of whether we know the remote and have a trusted key for it, is NOT verified!
                    // This is a serious issue and we cannot do a lot here.
                    transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                   $"Unable to verify the signature's incoming message from '{fullName}'." );
                    return null;
                }
                // This is a protocol error.
                // We do this after the signature check because an invali signature is more impacting.
                if( !timedNonce.CheckCreationTimeKind(transportManager.Logger, fullName ) )
                {
                    return null;
                }
                // The message's signature is verified and the CreationTime.Kind is UTC.
                // If we have no identified remote, we're done (with an invalid clock offset) but we compute the clockOffset
                // nevertheless (this may be a warning for the user).
                bool validClockOffset = false;
                TimeSpan clockOffset;
                if( remote == null )
                {
                    clockOffset = timedNonce.CreationTime - transportManager.ApplicationIdentityAgent.SystemClock.UtcNow;
                }
                else
                {
                    // Before impacting anything we check the nonce (that checks clock offset).
                    // The nonce (when validClockOffset is true) is always added: we don't want to
                    // forget a nonce because the remote is not trusted right now: if such message
                    // was to be replayed once the legitimate remote has been accepted, we would let
                    // a bad guy validate its connection... And if DisallowEviction is false: we're dead.
                    if( !remote.RemoteKeys.CheckNonce( transportManager.Logger,
                                                       in timedNonce,
                                                       out clockOffset,
                                                       out validClockOffset )
                        && validClockOffset )
                    {
                        // This looks like a replay attack.
                        // The log has been emitted. Give up.
                        return null;
                    }
                    // We have a known remote, validClockOffset may be false but it is is true then nonce is fine (and in the cache).

                    // Set the party's RemoteKeys on the incoming Transport.
                    // 
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
                    // We're almost done: if validClockOffset is true (then the nonce is okay) we can update the remote keys with the current one
                    // (if we trust the remote) and if we don't 
                    // If the AutoTrustKey does its job, we can accept the incoming connection immediately.
                    if( validClockOffset )
                    {
                        bool isalreadyTrusted = foundTrustKey;
                        foundTrustKey |= remote.RemoteKeys.OnReadIdentityKeys( transportManager.Logger, foundTrustKey, currentKeyData, currentKey );
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
                                           expectedCommonProtocolCount,
                                           canAutoTrust,
                                           supposedIdentity,
                                           timedNonce.Nonce,
                                           validClockOffset,
                                           clockOffset,
                                           currentKeyData,
                                           currentKey );
            }
        }

        static PeeringIssueKind DetectConfigurationOrTrustIssue( TransportManager transportManager,
                                                                 Transport incoming,
                                                                 InitialMessage initialMessage,
                                                                 ref TransportFeature? remote,
                                                                 bool foundTrustKey,
                                                                 out IRemoteParty? exists )
        {
            // If the remote is not found in the Listener's parties, it may nevertheless exist:
            // - It may be a Listener but on another tranport listener (UnsupportedTransportIncoming).
            // - It may be an Initiator (InitiatorConflict).
            // - The RemoteParty may exist but its TransportFeature is disabled (DisallowedTransportIncoming).
            if( remote == null )
            {
                exists = transportManager.ApplicationIdentityAgent.ApplicationIdentityService
                                         .AllRemotes.FirstOrDefault( r => r.FullName == initialMessage.FullName );
                if( exists == null )
                {
                    // We don't know the incoming at all.
                    return PeeringIssueKind.IncomingUnknwon;
                }
                remote = exists.GetFeature<TransportFeature>();
                if( remote == null )
                {
                    // The party exists but has no TransportFeature. From the TransportLayer point of view, it's as if it doesn't
                    // exist but this is more than that: it is disallowed.
                    return PeeringIssueKind.IncomingDisallowedTransport;
                }
                // The party exists...
                if( remote.TargetAddress != null )
                {
                    // ...and it is also an initiator.
                    return PeeringIssueKind.InitiatorConflict;
                }
                // ...and it listens on another TransportListener.
                Throw.DebugAssert( remote.IsListening );
                return PeeringIssueKind.IncomingUnsupportedTransport;
            }
            exists = remote.Party;
            // Computing the ternary issue.
            // On our side it's easy:
            bool weTrustHim = foundTrustKey;
            // But does he trust us? Thanks to the RemoteTrustInfo (SupposedIdentity and CanAutoTrust) in the InitialMessage we can
            // check whether or not he will be able to trust us.
            // If he can, everything is fine (he will obviously check this on its side with our identities and the signatures).
            // but if he cannot trust us, there is no point to continue because he will fail to accept us.
            bool heTrustsUs = true;
            var supposed = initialMessage.RemoteTrustInfo.SupposedIdentity;
            if( supposed == null || !remote.RemoteKeys.LocalKeys.Identities.Any( supposed.Equals ) )
            {
                // He doesn't know us... Can he auto trust us?
                if( !initialMessage.RemoteTrustInfo.CanAutoTrust )
                {
                    heTrustsUs = false;
                }
                else if( weTrustHim )
                {
                    transportManager.Logger.Warn( $"Remote '{initialMessage.FullName}' at '{incoming.RemoteEndPointDescription}' can auto trust us." );
                }
            }
            if( weTrustHim )
            {
                return heTrustsUs ? PeeringIssueKind.None : PeeringIssueKind.RequiresRemoteApproval;
            }
            return heTrustsUs ? PeeringIssueKind.RequiresLocalApproval : PeeringIssueKind.RequiresBothApproval;
        }

        static async ValueTask HandleConfigurationOrTrustIssueAsync( TransportManager transportManager,
                                                                     Transport incoming,
                                                                     InitialMessage initialMessage,
                                                                     TransportFeature? remote,
                                                                     PeeringIssueKind issue,
                                                                     IRemoteParty? existingParty )
        {
            // Send the RejectRemoteReply message, the PeeringIssueKind value should not be used here: the Zero Protocol must not
            // depend on this enum.
            var pIssue = issue switch
            {
                PeeringIssueKind.IncomingUnknwon => ZeroProtocol.ConfigurationOrTrustIssue.Unknwon,
                PeeringIssueKind.IncomingDisallowedTransport => ZeroProtocol.ConfigurationOrTrustIssue.DisallowedTransport,
                PeeringIssueKind.InitiatorConflict => ZeroProtocol.ConfigurationOrTrustIssue.InitiatorConflict,
                PeeringIssueKind.IncomingUnsupportedTransport => ZeroProtocol.ConfigurationOrTrustIssue.UnsupportedTransport,
                PeeringIssueKind.RequiresLocalApproval => ZeroProtocol.ConfigurationOrTrustIssue.ListenerRequiresLocalApproval,
                PeeringIssueKind.RequiresRemoteApproval => ZeroProtocol.ConfigurationOrTrustIssue.ListenerRequiresRemoteApproval,
                PeeringIssueKind.RequiresBothApproval => ZeroProtocol.ConfigurationOrTrustIssue.RequiresBothApproval,
                _ => Throw.NotSupportedException<ZeroProtocol.ConfigurationOrTrustIssue>()
            };
            // When there is a configuration issue or if the remote trust (or can) trust us, there is no point to tranfer an enlist url. 
            string? enlistUrl = issue is PeeringIssueKind.IncomingUnknwon
                                         or PeeringIssueKind.RequiresRemoteApproval
                                         or PeeringIssueKind.RequiresBothApproval
                                    ? transportManager.GetEnlistRemoteUrl( existingParty, initialMessage.DomainName )
                                    : null;
            var messageSent = await ZeroProtocol.SendRejectRemoteReplyMessageAsync( incoming,
                                                                                    remote?.RemoteKeys,
                                                                                    pIssue,
                                                                                    enlistUrl,
                                                                                    initialMessage.Nonce ).ConfigureAwait( false );
            if( !messageSent ) return;
            // Only if the transport has not been condemned.
            string? remoteEnlistUrl = null;
            if( issue is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval )
            {
                // Consider 3 bytes per Utf16 char... This is more than enough.
                using var enlistReplyMessage = await incoming.ReadNextAsync( 10 + 3 * ZeroProtocol.MaxEnlistUrlLength ).ConfigureAwait( false );
                if( !enlistReplyMessage.IsValid
                    || enlistReplyMessage.Protocol != MessageProtocol.ZeroProtocol
                    || enlistReplyMessage.Message.FirstSpan.Length == 0
                    || enlistReplyMessage.Message.FirstSpan[0] != ZeroProtocol.DNegoRequiredEnlistUrl )
                {
                    transportManager.Logger.Warn( $"Remote '{initialMessage.FullName}' at '{incoming.RemoteEndPointDescription}' replied an invalid RequiredEnlistUrl message." );
                    return;
                }
                if( !ZeroProtocol.ReadRequiredEnlistUrlMessage( enlistReplyMessage,
                                                                initialMessage.Nonce,
                                                                initialMessage.GetCurrentRemoteIdentityKey(),
                                                                out remoteEnlistUrl ) )
                {
                    // Weird...
                    transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                   $"Signature or nonce check failed for '{initialMessage.FullName}' at '{incoming.RemoteEndPointDescription}'." );
                    return;
                }
            }
            transportManager.OnIncomingConfigurationOrTrustIssue( initialMessage, remote, issue, remoteEnlistUrl );
        }

        static async ValueTask<MessageProtocol[]?> HandleProtocolsAsync( TransportManager transportManager,
                                                                         InitialMessage initialMessage,
                                                                         Transport incoming,
                                                                         TransportFeature remote )
        {
            // Let's check the full protocol list we received by intersecting it
            // with our declared protocol (and selecting the highest common version for each of them).
            MessageProtocol[] commonBest = remote.RegisteredProtocols.IntersectBy( initialMessage.AvailableProtocols, p => p.FullName )
                                                                     .GroupBy( p => p.Name )
                                                                     .Select( g => g.MaxBy( g => g.Version ) )
                                                                     .ToArray()!;
            // If the protocols from the other side don't satisfy us or if cannot satisfy him, we compute the
            // sets of missing on both sides for the PeeringIssues.
            // We send the MissingProtocolsMessage and let the caller close the connection (if it can do it quick enough).
            bool weAreSatisfied = commonBest.Length == remote.BestRegisteredProtocols.Count;
            bool heIsSatisfied = commonBest.Length == initialMessage.ExpectedCommonProtocolCount;
            if( !weAreSatisfied || !heIsSatisfied )
            {
                List<string>? weAreMissing = null;
                List<string>? heIsMissing = null;
                if( !weAreSatisfied )
                {
                    Throw.DebugAssert( commonBest.Length < remote.BestRegisteredProtocols.Count );
                    weAreMissing = remote.RegisteredProtocols.Where( p => !commonBest.Any( c => c.Name == p.Name ) )
                                                             .Select( p => p.FullName )
                                                             .ToList();
                    weAreMissing.Sort();
                }
                if( !heIsSatisfied )
                {
                    heIsMissing = initialMessage.AvailableProtocols.Where( p => !commonBest.Any( c => IsProtocol( c, p ) ) )
                                                                   .ToList();
                    heIsMissing.Sort();

                    static bool IsProtocol( MessageProtocol c, ReadOnlySpan<char> fullName )
                    {
                        return c.Name.Length > fullName.Length + 1
                               && fullName[c.Name.Length] == '.'
                               && fullName.StartsWith( c.Name, StringComparison.Ordinal );
                    }
                }
                transportManager.Logger.Error( $"Missing protocols for '{initialMessage.FullName}' at '{incoming.RemoteEndPointDescription}':{Environment.NewLine}" +
                                               $"We (listener) miss: {weAreMissing?.Concatenate()}{Environment.NewLine}" +
                                               $"He (initiator) misses: {heIsMissing?.Concatenate()}" );

                transportManager.OnMissingProtocolsIssues( initialMessage, remote, weAreMissing, heIsMissing );

                // If this message cannot be sent, we don't care.
                await ZeroProtocol.SendMissingProtocolsMessageAsync( incoming, initialMessage.Nonce, weAreMissing, heIsMissing ).ConfigureAwait( false );
                return null;
            }
            return commonBest;
        }


    }
}
