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
            var transport = await remote.TargetAddress.Type.TryConnectAsync( transportManager.Logger, remote.TargetAddress, cancellation.Token );
            if( transport != null )
            {
                TransportMessageImpl? firstAnswer = null;
                transport.SetCancellationSource( cancellation );
                bool disposeTransport = true;
                try
                {
                    // The CurrentVersion is necessarily supported. If this fails, it's because of a cancellation.
                    if( !await ZeroProtocol.SendInitialMessageAsync( remote, transport, ZeroProtocol.CurrentVersion ) )
                    {
                        // If we are canceled, let the finally destroy the new transport.
                        return null;
                    }
                    bool retriedDowngrade = false;
                    retry:
                    firstAnswer = await transport.ReadNextAsync( ZeroProtocol.FirstAnswerMaxLength );
                    if( !firstAnswer.IsValid || firstAnswer == TransportMessage.Empty )
                    {
                        if( _retryTickCount < 30 ) ++_retryTickCount;
                        transportManager.Logger.Error( $"Invalid first answer from remote '{remote.Party.FullName}'. Retrying in {_retryTickCount} seconds." );
                        return null;
                    }
                    var head = firstAnswer.Payload.First;
                    Debug.Assert( head.Length > 0, "The message is not empty (handled above)." );
                    switch( head.Span[0] )
                    {
                        case ZeroProtocol.DNegoUnknownRemote: 
                            {
                                string? userAcceptUri = ZeroProtocol.ReadUnknownRemoteReplyMessage( firstAnswer );
                                transportManager.Logger.Warn( $"The remote '{remote.Party.FullName}' doesn't know us. UserAcceptUri='{userAcceptUri}'. Retrying in 5 seconds." );
                                if( userAcceptUri != null )
                                {
                                    // TODO:
                                    // transportManager.InformUserAcceptUri( remote, userAcceptUri );
                                }
                                _retryTickCount = 5;
                                return null;
                            }
                        case ZeroProtocol.DRunByeBye:
                            {
                                var m = ZeroProtocol.ReadByeByeMessage( firstAnswer );
                                transportManager.Logger.Error( $"Received bye-bye message from '{remote.Party.FullName}': {m}" );
                                _retryTickCount = (int)Math.Floor( m.ShutUp.TotalSeconds );
                                return null;
                            }
                        case ZeroProtocol.DNegoDowngradeProtocol: 
                            {
                                int otherVersion = ZeroProtocol.ReadDowngradeProtocolReplyMessage( firstAnswer );
                                if( !retriedDowngrade )
                                {
                                    if( !await ZeroProtocol.SendInitialMessageAsync( remote, transport, otherVersion ) )
                                    {
                                        if( !cancellation.IsCancellationRequested )
                                        {
                                            transportManager.Logger.Error( $"The remote '{remote.Party.FullName}' expects the ZeroProtocol version '{otherVersion}'. "
                                                                         + $"Local '{ZeroProtocol.CurrentVersion}' cannot handle it. Retrying in 30 seconds." );
                                            _retryTickCount = 30;
                                        }
                                        // Canceled or bad version: let the finally condemn the new transport.
                                        return null;
                                    }
                                    firstAnswer.Dispose();
                                    retriedDowngrade = true;
                                    goto retry;
                                }
                                transportManager.Logger.Error( $"The remote '{remote.Party.FullName}' sent 2 downgrade protocol request. Retrying in 30 seconds." );
                                _retryTickCount = 30;
                                return null;
                            }
                        case ZeroProtocol.DNegoAcceptedProtocolsMessage: 
                            {
                                var protocolMap = ZeroProtocol.TryReadAcceptedProtocolsMessage( transportManager.Logger, firstAnswer, remote );
                                if( !protocolMap.IsValid )
                                {
                                    await ZeroProtocol.SendFinalMessageAsync( transport, remote, false );
                                    transportManager.Logger.Error( "Retrying in 30 seconds." );
                                    _retryTickCount = 30;
                                    return null;
                                }
                                // Sends the Ack.
                                if( await ZeroProtocol.SendFinalMessageAsync( transport, remote, true ) )
                                {
                                    // Accepts the transport.
                                    disposeTransport = false;
                                    transportManager.NewValidTransport( remote.Party, transport, protocolMap );
                                }
                                // Either we succeed or the successful SendFinalMessageAsync has been canceled: retry asap.
                                _retryTickCount = 1;
                                break;
                            }
                        case ZeroProtocol.DNegoEvictionDisallowed: 
                            {
                                transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' is already connected and its DisallowEviction is true. Retrying in 20 seconds." );
                                _retryTickCount = 20;
                                return null;
                            }
                        case ZeroProtocol.DNegoMissingProtocols: 
                            {
                                var missingProtocols = ZeroProtocol.ReadMissingProtocolsMessage( transportManager.Logger, firstAnswer, remote );
                                if( missingProtocols == null )
                                {
                                    return null;
                                }
                                transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' expects protocols: '{missingProtocols.Concatenate( "', '" )}'. Retrying in 30 seconds." );
                                _retryTickCount = 30;
                                return null;
                            }
                        default:
                            transportManager.Logger.Error( $"Invalid first answer from remote '{remote.Party.FullName}'." );
                            if( _retryTickCount < 30 ) ++_retryTickCount;
                            transportManager.Logger.Error( $"Invalid discriminator from remote '{remote.Party.FullName}'. Retrying in {_retryTickCount} seconds." ); return null;
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
