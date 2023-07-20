using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Buffers;
using System.Diagnostics;
using System.Text;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Handles calls to <see cref="TransportTypeService.TryConnectToAsync(IActivityLogger, IRemoteParty, object, CancellationToken)"/>.
    /// This BackTask is always retried until a valid (tested) outgoing connection is obtained or the remote party is destroyed.
    /// </summary>
    sealed class OutgoingConnectionBackTask : BackTask
    {
        TransportFeature? _remote;
        int _setupTick;
        int _retryTickCount;
        // No timeout on this cts: no Dispose required.
        CancellationTokenSource? _cts;
        Task<Transport?>? _result;
        int _tryCancelCount;
        int _tryCount;

        public override void OnDestroy( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null );
            if( _result != null ) CancelOperation( monitor, transportManager );
        }

        public override void Check( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null && _remote.TargetAddress != null );
            if( _remote.IsOff )
            {
                // If we have not started, there's nothing to do.
                if( _result != null )
                {
                    if( _tryCancelCount++ == 0 )
                    {
                        monitor.Info( $"Remote '{_remote.Party.FullName}' is off line. Stopping its OutgoingConnectionBackTask." );
                    }
                    if( !CancelOperation( monitor, transportManager ) )
                    {
                        Retry( 1 );
                    }
                    // If the CancelOperation succeeded, let this BackTask be reset.
                }
                return;
            }
            // If we have not started yet, let's start.
            if( _result == null )
            {
                Start( transportManager );
                Retry( _retryTickCount );
                return;
            }
            Debug.Assert( _cts != null );
            if( _result.IsCompleted )
            {
                if( !_result.IsCompletedSuccessfully || _result.Result == null )
                {
                    // We have an error or have been canceled... (cancellation is not by us and that is weird!, but this is the same: we must retry).
                    monitor.Warn( $"Failed to connect to '{_remote.Party.FullName}' (try n°{++_tryCount}). Retrying in {_retryTickCount} ticks.", _result.Exception );
                    Retry( _retryTickCount );
                    Setup( transportManager, _remote );
                }
                // Else the new transport has been provided to the TransportFeature
                // by TryConnectToAsync.
                // We are done, let this BackTask be reset.
                return;
            }
            // The attempt is still running. If it takes more than 2 ticks, this is weird.
            int howLong = FromSetupTick;
            // First, try to cancel the task thanks to the cts, and if it's really blocking, forget this blocked operation.
            // We always retry here (no Transport and the RemoteParty is not destroyed: we MUST continue).
            if( howLong == 2 && !_cts.IsCancellationRequested )
            {
                // This avoids the UnobservedTaskException on it.
                _result.ContinueWith( Util.ActionVoid, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default );
                _cts.Cancel();
                // The only reason why the task will not be canceled is because of a serious bug: the cancellation token is
                // ignored by at least one blocking step. This should not happen but we handle this pathological case anyway below.
                Retry( 1 );
                return;
            }
            if( howLong > 4 )
            {
                monitor.Error( $"Connection to '{_remote.Party.FullName}' is blocking and the operation cannot be canceled! Forgetting it and retrying." );
                // Sets the CurrentTick before calling Setup again.
                Retry( _retryTickCount );
                Setup( transportManager, _remote );
                return;
            }
            Retry( 1 );
        }

        bool CancelOperation( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null && _result != null && _cts != null );

            // If the result has been canceled or is faulted, we don't care anymore.
            // But if a transport has been created, we must destroy it.
            if( KillExistingTransport( _result, transportManager ) ) return true;
            // This backTask is still running: use the cts to cancel it if not already signaled.
            if( !_cts.IsCancellationRequested )
            {
                _cts.Cancel();
            }
            // There is little chance that the task be immediately completed but
            // it doesn't cost much to test it here to avoid a tick.
            return KillExistingTransport( _result, transportManager );

            static bool KillExistingTransport( Task<Transport?> result, TransportManager transportManager )
            {
               if( result.IsCompleted )
               {
                    if( result.IsCompletedSuccessfully && result.Result != null )
                    {
                        transportManager.KillTransport( result.Result );
                    }
                    return true;
                }
                return false;
            }
        }

        int FromSetupTick => CurrentTick - _setupTick;

        public void Setup( TransportManager transportManager, TransportFeature remote )
        {
            Debug.Assert( remote != null && remote.TargetAddress != null && remote != null );
            _remote = remote;
            Debug.Assert( CurrentTick >= 1 );
            _setupTick = CurrentTick;
            _retryTickCount = CurrentTick;
            if( _retryTickCount == 1 )
            {
                // Immediate start.
                Start( transportManager );
            }
        }

        private void Start( TransportManager transportManager )
        {
            Debug.Assert( _remote != null );
            _cts = new CancellationTokenSource();
            _result = TryConnectToAsync( transportManager, _remote, _cts );
            // This avoids any UnobservedTaskException on it.
            _result.ContinueWith( Util.ActionVoid, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default );
        }

        public override void Reset()
        {
            _remote = null;
            _tryCancelCount = 0;
            _tryCount = 0;
            _cts = null;
        }

        async Task<Transport?> TryConnectToAsync( TransportManager transportManager,
                                                  TransportFeature remote,
                                                  CancellationTokenSource cancellation )
        {
            Debug.Assert( remote.OutgoingInitialMessage != null, "Feature initialization is done." );
            Debug.Assert( remote.TargetAddress != null );
            var transport = await remote.TargetAddress.Type.TryConnectAsync( transportManager.Logger,
                                                                             remote.TargetAddress,
                                                                             remote.RemoteKeys,
                                                                             cancellation.Token );
            if( transport != null )
            {
                Debug.Assert( transport.RemoteKeys == remote.RemoteKeys );
                IncomingMessage? firstAnswer = null;
                transport.SetCancellationSource( cancellation );
                bool disposeTransport = true;
                try
                {
                    // The CurrentVersion is necessarily supported. If this fails, it's because of a cancellation.
                    var sentNonce = await ZeroProtocol.SendInitialMessageAsync( transportManager.SystemClock, transport, remote.OutgoingInitialMessage, ZeroProtocol.CurrentVersion );
                    if( !sentNonce.HasValue )
                    {
                        // If we are canceled, let the finally destroy the new transport.
                        return null;
                    }
                    // Retrying is done only once when a DonwgradeProtocolVersion is received.
                    bool retriedDowngrade = false;
                    retry:
                    firstAnswer = await transport.ReadNextAsync( ZeroProtocol.FirstAnswerMaxLength );
                    if( !firstAnswer.IsValid || firstAnswer == IncomingMessage.Empty )
                    {
                        if( _retryTickCount < 30 ) ++_retryTickCount;
                        transportManager.Logger.Error( $"Invalid first answer from remote '{remote.Party}'. Retrying in {_retryTickCount} seconds." );
                        return null;
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
                                    _retryTickCount = 10;
                                    return null;
                                }
                                // We have data but if the nonce we sent is not the one we have in reply, this is a serious issue.
                                if( nonceFailure )
                                {
                                    transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                                   $"The remote '{remote.Party}' sent an invalid Nonce. Retrying in 30 seconds." );
                                    _retryTickCount = 30;
                                    return null;
                                }
                                // We are totally unknown to the target (the message is not signed in this case because the remote system must not
                                // pick a Localkeys provider at random among its root and potential TenantDomains).
                                if( currentKeyData == null )
                                {
                                    Debug.Assert( !signatureVerified );
                                    transportManager.Logger.Warn( $"The remote '{remote.Party}' doesn't know us at all. EnlistUrl='{enlistUrl}'. Retrying in 5 seconds." );
                                    transportManager.TargetRequiresCreationOrApproval( remote, enlistUrl, false );
                                    _retryTickCount = 5;
                                    return null;
                                }
                                // The remote knowns our existence but doesn't trust us.
                                // Weird: the sent signatures cannot be verified.
                                if( !signatureVerified )
                                {
                                    transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                                   $"Unable to verify the signature's reply message from '{remote.Party}'. Retrying in 10 seconds." );
                                    _retryTickCount = 10;
                                    return null;
                                }
                                remote.RemoteKeys.OnReadIdentityKeys( transportManager.Logger, foundTrustedKey, currentKeyData, currentKey );
                                transportManager.Logger.Warn( $"The remote '{remote.Party}' knows about us but doesn't trust our identity. EnlistUrl='{enlistUrl}'. Retrying in 5 seconds." );
                                transportManager.TargetRequiresCreationOrApproval( remote, enlistUrl, true );
                                _retryTickCount = 5;
                                return null;
                            }
                        case ZeroProtocol.DNegoOffRemote:
                            {
                                var shutUp = ZeroProtocol.ReadOffRemoteMessage( transportManager.Logger, remote, firstAnswer, sentNonce.Value );
                                // If the nonce or the verification failed, retries in 30 seconds.
                                _retryTickCount = shutUp.HasValue ? (int)Math.Floor( shutUp.Value.TotalSeconds ) : 30;
                                transportManager.Logger.Trace( $"Retrying in {_retryTickCount} seconds." );
                                return null;
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
                                    // If the nonce or the verification failed, retries in 10 seconds.
                                    transportManager.Logger.Trace( $"Retrying in 10 seconds." );
                                    _retryTickCount = 10;
                                    return null;
                                }
                                // If we trust the remote and the "AllowClockSet" configuration is true, update our clock.
                                if( foundTrustedKey && remote.RemoteKeys.AllowClockSet )
                                {
                                    bool success = await transportManager.TryAdjustSystemTimeAsync( remote.Party, msgReceivedTime - remoteTime );
                                    if( success )
                                    {
                                        // On success, retry quickly.
                                        transportManager.Logger.Trace( $"Retrying in 1 second." );
                                        _retryTickCount = 1;
                                        return null;
                                    }
                                }
                                _retryTickCount = 20;
                                transportManager.Logger.Trace( $"Retrying in 20 seconds." );
                                return null;
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
                                            _retryTickCount = 60;
                                        }
                                        // Canceled or bad version: let the finally condemn the new transport.
                                        return null;
                                    }
                                    firstAnswer.Dispose();
                                    retriedDowngrade = true;
                                    goto retry;
                                }
                                transportManager.Logger.Error( $"The remote '{remote.Party}' sent 2 downgrade protocol requests. Retrying in 30 seconds." );
                                _retryTickCount = 30;
                                return null;
                            }
                        case ZeroProtocol.DNegoAcceptedProtocolsMessage: 
                            {
                                var protocolMap = ZeroProtocol.TryReadAcceptedProtocolsMessage( transportManager,
                                                                                                firstAnswer,
                                                                                                remote,
                                                                                                sentNonce.Value,
                                                                                                out var finalClockOffset );
                                if( !protocolMap.IsValid )
                                {
                                    await ZeroProtocol.SendFinalFailureMessageAsync( transport );
                                    transportManager.Logger.Error( "Retrying in 60 seconds." );
                                    _retryTickCount = 60;
                                    return null;
                                }
                                // We are ready to accept the transport.
                                // Sends the Initiator (Outgoing) Ack.
                                if( await ZeroProtocol.SendFinalSuccessMessageAsync( transport, remote, sentNonce.Value, finalClockOffset ) )
                                {
                                    // Accepts the transport.
                                    disposeTransport = false;
                                    transportManager.NewValidTransport( remote.Party, transport, protocolMap, finalClockOffset );
                                }
                                // Either we succeed or the successful SendFinalMessageAsync has been canceled: retry asap (on success, the BackTask will
                                // be reset).
                                _retryTickCount = 1;
                                break;
                            }
                        case ZeroProtocol.DNegoEvictionDisallowed: 
                            {
                                var valid = ZeroProtocol.ReadEvictionDisallowedMessage( transportManager.Logger, remote, firstAnswer, sentNonce.Value );
                                if( valid )
                                {
                                    transportManager.Logger.Error( $"Remote '{remote.Party}' is already connected and its DisallowEviction is true. Retrying in 20 seconds." );
                                    _retryTickCount = 20;
                                }
                                else
                                {
                                    transportManager.Logger.Info( "Retrying in 30 seconds." );
                                    _retryTickCount = 30;
                                }
                                return null;
                            }
                        case ZeroProtocol.DNegoMissingProtocols: 
                            {
                                var missingProtocols = ZeroProtocol.TryReadMissingProtocolsMessage( transportManager.Logger, firstAnswer, sentNonce.Value, remote );
                                if( missingProtocols == null )
                                {
                                    transportManager.Logger.Info( "Retrying in 30 seconds." );
                                    _retryTickCount = 30;
                                    return null;
                                }
                                transportManager.Logger.Error( $"Remote '{remote.Party}' expects protocols: '{missingProtocols.Concatenate( "', '" )}'. Retrying in 30 seconds." );
                                _retryTickCount = 30;
                                return null;
                            }
                        default:
                            if( _retryTickCount < 60 ) ++_retryTickCount;
                            transportManager.Logger.Error( $"Invalid discriminator from remote '{remote.Party}'. Retrying in {_retryTickCount} seconds." ); return null;
                    }
                }
                finally
                {
                    firstAnswer?.Dispose();
                    if( disposeTransport )
                    {
                        transportManager.KillTransport( transport );
                        transport = null;
                    }
                }
            }
            return transport;
        }
    }
}
