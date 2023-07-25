using CK.AppIdentity.KeyManagement;
using CK.Core;
using Microsoft.VisualBasic;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using static CK.Core.ActivityMonitorSimpleCollector;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Handles calls to <see cref="TransportTypeService.TryConnectToAsync(IActivityLogger, IRemoteParty, object, CancellationToken)"/>.
    /// This BackTask is always retried until a valid (tested) outgoing connection is obtained or the remote party is destroyed.
    /// </summary>
    sealed class OutgoingConnectionBackTask : BackTask
    {
        TransportFeature? _remote;
        // No timeout on this cts: no Dispose required.
        CancellationTokenSource? _cts;
        Task<int>? _result;
        // Current start or restart count.
        int _startCount;
        // Current start time.
        DateTime _startTime;
        // Transition to true when cancelling because remote.IsOff.
        bool _offlineDecision;

        public override void OnDestroy( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null );
            if( IsStarted && !_cts.IsCancellationRequested ) CancelOperation( monitor, offline: true );
        }

        [MemberNotNullWhen( true, nameof( _result ), nameof( _cts ), nameof( _remote ) )]
        bool IsStarted
        {
            get
            {
                Debug.Assert( _remote != null );
                Debug.Assert( _result == null || _cts != null, "_result != null => _cts != null" );
                return _result != null;
            }
        }

        public override void Check( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null && _remote.TargetAddress != null );
            if( IsStarted )
            {
                // Handles a completed result first.
                if( _result.IsCompleted )
                {
                    if( !_result.IsCompletedSuccessfully )
                    {
                        // We have an error or have been canceled..
                        // The error is typically a parsing error of an incoming message, we increase the retry time.
                        int retryDelay = Math.Max( _startCount + 1, 30 );
                        if( _result.IsFaulted )
                        {
                            monitor.Error( $"Unhandled error while connecting to '{_remote.Party}' (try n°{_startCount}). Retrying in {retryDelay} second.", _result.Exception );
                        }
                        else
                        {
                            Debug.Assert( _result.IsCanceled );
                            if( !_cts.IsCancellationRequested )
                            {
                                // Cancellation is not by us and that is weird!
                                monitor.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                               $"Unexpected cancellation while connecting to '{_remote.Party}' (try n°{_startCount}). Retrying in {retryDelay} second." );
                            }
                            // Else, regular case: cancellation belongs to us, it is a timeout or a offline decision.
                            // On timeout the delay is the same as for an unexpected error.
                        }
                        if( !_offlineDecision ) Retry( retryDelay );
                    }
                    else
                    {
                        // Successful completion: either the new transport has been provided to the TransportFeature
                        // by TryConnectToAsync or we have a retry delay.
                        int delay = _result.Result;
                        if( delay > 0 ) Retry( delay );
                        // Else (delay is 0), we are done, let this BackTask be reset.
                    }
                    // Forget the completed result.
                    _result = null;
                    return;
                }
                // If CancelOperation signaled the CTS and the task is still alive, this is weird.
                if( _cts.IsCancellationRequested )
                {
                    monitor.Warn( ActivityMonitor.Tags.ToBeInvestigated,
                                  $"Failure to complete cancellation of OutgoingConnectionBackTask for Remote '{_remote.Party}'." +
                                  $" Forgetting the current Task and retrying in 30 seconds." );
                    _result = null;
                    if( !_offlineDecision ) Retry( 30 );
                    return;
                }
                // If remote became off, we cancel this back task. Retrying is in 1 tick: the task should be canceled then.
                if( _remote.IsOff )
                {
                    CancelOperation( monitor, offline: true );
                    return;
                }
                // The attempt is still running. If it takes more than 2 seconds, this is weird.
                var delta = DateTime.UtcNow - _startTime;
                if( delta > TimeSpan.FromMilliseconds( TransportManager.NegotiationTimeout ) )
                {
                    monitor.Trace( $"Timeout ({delta.TotalMilliseconds:G0} ms) while connecting to remote '{_remote.Party}'." );
                    CancelOperation( monitor, false );
                }
                Retry( 1 );   // If the previous tick canceled the task and we are not completed, this is weird.
            }
            else
            {
                // Check that the remote is alive before starting.
                if( !_remote.IsOff ) StartOrRestart( transportManager );
                return;
            }
        }

        void CancelOperation( IActivityMonitor monitor, bool offline )
        {
            Debug.Assert( IsStarted && !_cts.IsCancellationRequested );

            if( offline )
            {
                _offlineDecision = true;
                monitor.Info( $"Remote '{_remote.Party}' is off line. Stopping its OutgoingConnectionBackTask." );
            }
            // We signal the cancelation but wait one tick to handle it.
            _cts.Cancel();
            // This avoids any UnobservedTaskException on the result if cancellation fails to be honored in 1 tick.
            _result.ContinueWith( Util.ActionVoid, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default );
            Retry( 1 );
        }

        public void OnInitialize( TransportManager transportManager, TransportFeature remote, int startDelay )
        {
            Debug.Assert( remote != null && remote.TargetAddress != null && _remote == null );
            _remote = remote;
            if( startDelay == 0 )
            {
                // Immediate start.
                StartOrRestart( transportManager );
            }
            else
            {
                Retry( startDelay );
            }
        }

        void StartOrRestart( TransportManager transportManager )
        {
            Debug.Assert( _remote != null );
            // Reuse the same CTS if possible.
            if( _cts == null || _cts.IsCancellationRequested )
            {
                _cts = new CancellationTokenSource();
            }
            _startCount = 0;
            _startTime = DateTime.UtcNow;
            _result = TryConnectToAsync( transportManager, _remote, _cts, _startCount++ );
            Retry( 1 );
        }

        public override void Reset()
        {
            _remote = null;
            _cts = null;
        }

        static async Task<int> TryConnectToAsync( TransportManager transportManager,
                                                  TransportFeature remote,
                                                  CancellationTokenSource cancellation,
                                                  int currentTryCount )
        {
            Debug.Assert( remote.OutgoingInitialMessage != null, "Feature initialization is done." );
            Debug.Assert( remote.TargetAddress != null );

            Transport? transport;
            try
            {
                transport = await remote.TargetAddress.Type.TryConnectAsync( transportManager.Logger,
                                                                             remote.TargetAddress,
                                                                             remote.RemoteKeys,
                                                                             cancellation.Token );
                if( transport == null )
                {
                    return OnFailedTransportCreation( transportManager.Logger, currentTryCount, $"Unable to open connection to '{remote.Party}' at '{remote.TargetAddress}'.", null );
                }
            }
            catch( Exception ex )
            {
                return OnFailedTransportCreation( transportManager.Logger, currentTryCount, $"Error while opening connection to '{remote.Party}' at '{remote.TargetAddress}'.", ex );
            }

            Debug.Assert( transport.RemoteKeys == remote.RemoteKeys );
            IncomingMessage? firstAnswer = null;
            transport.SetCancellationSource( cancellation );
            bool killTransport = true;
            try
            {
                // The CurrentVersion is necessarily supported. If this fails, it's because of a cancellation.
                var sentNonce = await ZeroProtocol.SendInitialMessageAsync( transportManager.SystemClock, transport, remote.OutgoingInitialMessage, ZeroProtocol.CurrentVersion );
                if( !sentNonce.HasValue )
                {
                    // If we are canceled, let the finally kill the new transport.
                    // The retry will be ignored since this back task is canceled.
                    return 1;
                }
                // Retrying is done only once when a DonwgradeProtocolVersion is received.
                bool retriedDowngrade = false;
                retry:
                firstAnswer = await transport.ReadNextAsync( ZeroProtocol.FirstAnswerMaxLength ).ConfigureAwait( false );
                if( !firstAnswer.IsValid || firstAnswer == IncomingMessage.Empty )
                {
                    return OnInvalidMessage( transportManager, currentTryCount, $"Invalid first answer from remote '{remote.Party}'." );
                }
                var head = firstAnswer.Message.First;
                Debug.Assert( head.Length > 0, "The message is not empty (handled above)." );
                switch( head.Span[0] )
                {
                    case ZeroProtocol.DNegoUnknownRemote:
                        {
                            RemoteIdentityKey? trustedIdentity = remote.RemoteKeys.TrustedIdentity;
                            ZeroProtocol.ReadUnknownRemoteReplyMessage( firstAnswer,
                                                                        sentNonce.Value,
                                                                        trustedIdentity,
                                                                        out bool remoteVerificationFailure,
                                                                        out bool nonceFailure,
                                                                        out string? enlistUrl,
                                                                        out RemoteIdentityKeyData? currentKeyData,
                                                                        out bool foundTrustedKey,
                                                                        out RemoteIdentityKey? currentKey,
                                                                        out bool signatureVerified );
                            // Weird case: the remote couldn't verify our signature or the nonce check failed.
                            // We don't have any other available data.
                            if( remoteVerificationFailure )
                            {
                                transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                               $"The remote '{remote.Party}' was unable to verify our signature or the nonce check failed. Retrying in 10 seconds." );
                                return 10;
                            }
                            // We have data but if the nonce we sent is not the one we have in reply, this is a serious issue.
                            if( nonceFailure )
                            {
                                transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                               $"The remote '{remote.Party}' sent an invalid Nonce. Retrying in 30 seconds." );
                                return 30;
                            }
                            // We are totally unknown to the target (the message is not signed in this case because the remote system must not
                            // pick a Localkeys provider at random among its root and potential TenantDomains).
                            if( currentKeyData == null )
                            {
                                Debug.Assert( !signatureVerified );
                                transportManager.Logger.Warn( $"The remote '{remote.Party}' doesn't know us at all. EnlistUrl='{enlistUrl}'. Retrying in 5 seconds." );
                                transportManager.TargetRequiresCreationOrApproval( remote, enlistUrl, false );
                                return 5;
                            }
                            // The remote knowns our existence but doesn't trust us.
                            // Weird: the sent signatures cannot be verified.
                            if( !signatureVerified )
                            {
                                transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                               $"Unable to verify the signature's reply message from '{remote.Party}'. Retrying in 30 seconds." );
                                return 30;
                            }
                            remote.RemoteKeys.OnReadIdentityKeys( transportManager.Logger, foundTrustedKey, currentKeyData, currentKey );
                            transportManager.Logger.Warn( $"The remote '{remote.Party}' knows about us but doesn't trust our identity. EnlistUrl='{enlistUrl}'. Retrying in 5 seconds." );
                            transportManager.TargetRequiresCreationOrApproval( remote, enlistUrl, true );
                            return 5;
                        }
                    case ZeroProtocol.DNegoOffRemote:
                        {
                            var shutUp = ZeroProtocol.ReadOffRemoteMessage( transportManager.Logger, remote, firstAnswer, sentNonce.Value );
                            // If the nonce or the verification failed (this has been logged), retries in 30 seconds.
                            int retryDelay = shutUp.HasValue ? (int)Math.Floor( shutUp.Value.TotalSeconds ) : 30;
                            transportManager.Logger.Trace( $"Retrying in {retryDelay} seconds." );
                            return retryDelay;
                        }
                    case ZeroProtocol.DNegoInvalidClockOffset:
                        {
                            DateTime msgReceivedTime = transportManager.SystemClock.UtcNow;
                            if( !ZeroProtocol.ReadInvalidClockOffsetMessage( transportManager.Logger,
                                                                             remote,
                                                                             firstAnswer,
                                                                             sentNonce.Value,
                                                                             out var remoteClockOffset,
                                                                             out var remoteTime,
                                                                             out var foundTrustedKey ) )
                            {
                                // If the nonce or the verification failed, retries in 30 seconds.
                                transportManager.Logger.Trace( $"Retrying in 30 seconds." );
                                return 30;
                            }
                            // If we trust the remote and the "AllowClockSet" configuration is true, try to update our clock.
                            if( foundTrustedKey && remote.RemoteKeys.AllowClockSet )
                            {
                                bool success = await transportManager.TryAdjustSystemTimeAsync( remote.Party, msgReceivedTime - remoteTime ).ConfigureAwait( false );
                                if( success )
                                {
                                    // On success, retry quickly.
                                    transportManager.Logger.Trace( $"Retrying in 1 second." );
                                    return 1;
                                }
                            }
                            transportManager.Logger.Trace( $"Retrying in 20 seconds." );
                            return 20;
                        }
                    case ZeroProtocol.DNegoDowngradeProtocol:
                        {
                            int otherVersion = ZeroProtocol.ReadDowngradeProtocolReplyMessage( firstAnswer );
                            if( !retriedDowngrade )
                            {
                                sentNonce = await ZeroProtocol.SendInitialMessageAsync( transportManager.SystemClock, transport, remote.OutgoingInitialMessage, otherVersion );
                                if( !sentNonce.HasValue )
                                {
                                    if( !cancellation.IsCancellationRequested )
                                    {
                                        transportManager.Logger.Error( $"The remote '{remote.Party}' expects the ZeroProtocol version '{otherVersion}'. "
                                                                     + $"Local '{ZeroProtocol.CurrentVersion}' cannot handle it. Retrying in 60 seconds." );
                                        return 60;
                                    }
                                    // Canceled: the retry will be ignored since this back task is canceled.
                                    return 1;
                                }
                                firstAnswer.Dispose();
                                retriedDowngrade = true;
                                goto retry;
                            }
                            transportManager.Logger.Error( $"The remote '{remote.Party}' sent 2 downgrade protocol requests. Retrying in 30 seconds." );
                            return 30;
                        }
                    case ZeroProtocol.DNegoAcceptedProtocolsMessage:
                        {
                            var protocolMap = ZeroProtocol.TryReadAcceptedProtocolsMessage( transportManager,
                                                                                            firstAnswer,
                                                                                            remote,
                                                                                            sentNonce.Value,
                                                                                            out var foundTrustKey,
                                                                                            out var finalClockOffset );
                            if( !protocolMap.IsValid )
                            {
                                await ZeroProtocol.SendFinalFailureMessageAsync( transport ).ConfigureAwait( false );
                                if( !foundTrustKey )
                                {
                                    // This should not happen because the InitialMessage.RemoteTrustInfo told the remote listener
                                    // that we didn't trust him and had no way to automatically trust him, but this is safer
                                    // to control this here.
                                    transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                                   $"We eventually don't trust the remote '{remote.Party}'. Retrying in 30 seconds." );
                                }
                                else
                                {
                                    transportManager.Logger.Error( "Retrying in 30 seconds." );
                                }
                                return 30;
                            }
                            // We are ready to accept the transport.
                            // Sends the Initiator (Outgoing) Ack.
                            if( await ZeroProtocol.SendFinalSuccessMessageAsync( transport, remote, sentNonce.Value, finalClockOffset ).ConfigureAwait( false ) )
                            {
                                // Accepts the transport.
                                killTransport = false;
                                transportManager.NewValidTransport( remote.Party, transport, protocolMap, finalClockOffset );
                                // Successful SendFinalMessageAsync: retry asap, the BackTask will be reset).
                                return 0;
                            }
                            // Canceled: the retry will be ignored since this back task is canceled.
                            return 1;
                        }
                    case ZeroProtocol.DNegoEvictionDisallowed:
                        {
                            var valid = ZeroProtocol.ReadEvictionDisallowedMessage( transportManager.Logger, remote, firstAnswer, sentNonce.Value );
                            if( valid )
                            {
                                transportManager.Logger.Error( $"Remote '{remote.Party}' is already connected and its DisallowEviction is true. Retrying in 20 seconds." );
                                return 20;
                            }
                            transportManager.Logger.Info( "Retrying in 30 seconds." );
                            return 30;
                        }
                    case ZeroProtocol.DNegoMissingProtocols:
                        {
                            var missingProtocols = ZeroProtocol.TryReadMissingProtocolsMessage( transportManager.Logger, firstAnswer, sentNonce.Value, remote );
                            if( missingProtocols == null )
                            {
                                transportManager.Logger.Info( "Retrying in 30 seconds." );
                                return 30;
                            }
                            transportManager.Logger.Error( $"Remote '{remote.Party}' expects protocols: '{missingProtocols.Concatenate( "', '" )}'. Retrying in 30 seconds." );
                            return 30;
                        }
                    default:
                        return OnInvalidMessage( transportManager, currentTryCount, $"Invalid discriminator from remote '{remote.Party}'." );
                }
            }
            finally
            {
                firstAnswer?.Dispose();
                if( killTransport )
                {
                    transportManager.KillTransport( transport );
                }
            }

            static int OnFailedTransportCreation( IParallelLogger logger, int currentTryCount, string msg, Exception? ex )
            {
                var retryDelay = Math.Max( currentTryCount + 1, 5 );
                logger.Error( $"{msg} Retrying in {retryDelay} seconds.", ex );
                return retryDelay;
            }


            static int OnInvalidMessage( TransportManager transportManager, int currentTryCount, string msg )
            {
                int retryDelay = Math.Max( currentTryCount + 1, 30 );
                transportManager.Logger.Error( $"{msg} Retrying in {retryDelay} seconds." );
                return retryDelay;
            }
        }
    }
}
