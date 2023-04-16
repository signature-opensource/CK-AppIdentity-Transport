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
        TransportTypeAddress? _target;
        private int _setupTick;
        CancellationTokenSource? _cts;
        Task<Transport?>? _result;
        int _tryCancelCount;
        int _tryCount;

        public override void OnDestroy( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null && _result != null && _cts != null );
            CancelOperation( monitor, transportManager );
        }

        public override void Check( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null && _target != null && _result != null && _cts != null );
            if( _remote.Party.IsDestroyed )
            {
                if( _tryCancelCount++ == 0 )
                {
                    monitor.Trace( $"Remote '{_remote.Party.FullName}' destroyed. Stopping its OutgoingConnectionBackTask." );
                }
                if( !CancelOperation( monitor, transportManager ) )
                {
                    Retry( 1 );
                }
                // If the CancelOperation succeeded, let this BackTask be reset.
            }
            else if( _result.IsCompleted )
            {
                if( !_result.IsCompletedSuccessfully || _result.Result == null )
                {
                    // We have an error or have been canceled... (cancellation is not by us and that is weird!, but this is the same: we must retry).
                    monitor.Warn( $"Failed to connect to '{_remote.Party.FullName}' (try n°{++_tryCount}). Retrying.", _result.Exception );
                    Setup( transportManager, _remote, _target );
                    Retry( 1 );
                }
                // Else the new transport has been provided to the TransportFeature
                // by TransportTypeService.TryConnectToAsync.
                // We are done, let this BackTask be reset.
            }
            else
            {
                // The attempt is still running. If it takes more that 2 ticks, this is weird.
                // First, try to cancel the task thanks to the cts, and if it's really blocking, forget this blocked operation.
                // We always retry here (no Transport and the RemoteParty is not destroyed: we MUST continue).
                int howLong = FromSetupTick;
                if( howLong > 1 )
                {
                    if( !_cts.IsCancellationRequested )
                    {
                        // This avoids the UnobservedTaskException on it.
                        _result.ContinueWith( Util.ActionVoid, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default );
                        _cts.Cancel();
                        // The only reason why the task will not be canceled is because of a serious bug: the cancellation token is
                        // ignored by at least one blocking step. This should not happen but we handle this pathological case anyway below.
                    }
                    else
                    {
                        if( howLong > 4 )
                        {
                            monitor.Error( $"Connection to '{_remote.Party.FullName}' is blocking and the operation cannot be canceled! Forgetting it and retrying." );
                            Setup( transportManager, _remote, _target );
                        }
                    }
                }
                Retry( 1 );
            }
        }

        bool CancelOperation( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remote != null && _result != null && _cts != null );

            // If the result has been canceled or is faulted, we don't care anymore.
            // But if a transport has been created, we must destroy it.
            if( OnCompleted( _result, transportManager ) ) return true;
            // This backTask is still running: use the cts to cancel it if not already signaled.
            if(  !_cts.IsCancellationRequested )
            {
                // This avoids the UnobservedTaskException on it.
                _result.ContinueWith( Util.ActionVoid, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default );
                _cts.Cancel();
            }
            // There is little chance that the task be immediately completed but
            // it doesn't cost much to test it here to avoid a tick.
            return OnCompleted( _result, transportManager );

            static bool OnCompleted( Task<Transport?> result, TransportManager transportManager )
            {
               if( result.IsCompleted )
                {
                    if( result.IsCompletedSuccessfully && result.Result != null )
                    {
                        transportManager.CondemnTransport( result.Result );
                    }
                    return true;
                }
                return false;
            }
        }

        int FromSetupTick => CurrentTick - _setupTick;

        public void Setup( TransportManager transportManager, TransportFeature remote, TransportTypeAddress target )
        {
            Debug.Assert( remote != null && target != null && remote != null );
            _cts = new CancellationTokenSource();
            _result = TryConnectToAsync( transportManager, remote, target, _cts );
            _remote = remote;
            _target = target;
            _setupTick = CurrentTick;
        }

        public override void Reset()
        {
            _remote = null;
            _target = null;
            _tryCancelCount = 0;
            _tryCount = 0;
            _cts = null;
        }

        async Task<Transport?> TryConnectToAsync( TransportManager transportManager,
                                                  TransportFeature remote,
                                                  TransportTypeAddress typedAddress,
                                                  CancellationTokenSource cancellation )
        {
            Debug.Assert( remote.OutgoingInitialMessage != null, "Feature initialization is done." );
            var transport = await typedAddress.Type.TryConnectAsync( transportManager.Logger, typedAddress, cancellation.Token );
            if( transport != null )
            {
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
                    var firstAnswer = await transport.ReadNextAsync( ZeroProtocol.FirstAnswerMaxLength );
                    if( !firstAnswer.IsValid || firstAnswer == TransportMessage.Empty )
                    {
                        transportManager.Logger.Error( $"Invalid first answer from remote '{remote.Party.FullName}'." );
                        return null;
                    }
                    var head = firstAnswer.Message.First;
                    Debug.Assert( head.Length > 0, "The message is not empty (handled above)." );
                    switch( head.Span[0] )
                    {
                        case ZeroProtocol.DiscrimnatorUnknownRemote: 
                            {

                                string? userAcceptUri = ZeroProtocol.ReadUnknownRemoteReplyMessageAsync( firstAnswer );
                                transportManager.Logger.Warn( $"The remote '{remote.Party.FullName}' doesn't know us. UserAcceptUri='{userAcceptUri}'." );
                                if( userAcceptUri != null )
                                {
                                    // TODO:
                                    // transportManager.InformUserAcceptUri( remote, userAcceptUri );
                                }
                                return null;
                            }
                        case ZeroProtocol.DiscriminatorDowngradeProtocol: 
                            {
                                int otherVersion = ZeroProtocol.ReadDowngradeProtocolReplyMessage( firstAnswer );
                                if( !retriedDowngrade )
                                {
                                    if( !await ZeroProtocol.SendInitialMessageAsync( remote, transport, otherVersion ) )
                                    {
                                        if( !cancellation.IsCancellationRequested )
                                        {
                                            transportManager.Logger.Error( $"The remote '{remote.Party.FullName}' expects the ZeroProtocol version '{otherVersion}'. Local '{ZeroProtocol.CurrentVersion}' cannot handle it." );
                                        }
                                        // Canceled or bad version: let the finally condemn the new transport.
                                        return null;
                                    }
                                    retriedDowngrade = true;
                                    goto retry;
                                }
                                transportManager.Logger.Error( $"The remote '{remote.Party.FullName}' sent 2 downgrade protocol request." );
                                return null;
                            }
                        case ZeroProtocol.DiscriminatorAcceptedProtocolsMessage: 
                            {
                                var protocolMap = ZeroProtocol.TryReadAcceptedProtocolsMessage( transportManager.Logger, firstAnswer, remote );
                                if( !protocolMap.IsValid )
                                {
                                    await ZeroProtocol.SendFinalMessageAsync( transport, remote, false );
                                    return null;
                                }
                                // Sends the Ack.
                                if( await ZeroProtocol.SendFinalMessageAsync( transport, remote, true ) )
                                {
                                    // Accepts the transport.
                                    disposeTransport = false;
                                    transportManager.NewValidTransport( remote.Party, transport, protocolMap );
                                }
                                break;
                            }
                        case ZeroProtocol.DiscriminatorMissingProtocols: 
                            {
                                var missingProtocols = ZeroProtocol.ReadMissingProtocolsMessage( transportManager.Logger, firstAnswer, remote );
                                if( missingProtocols == null )
                                {
                                    return null;
                                }
                                transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' expects protocols: '{missingProtocols.Concatenate( "', '" )}'." );
                                return null;
                            }
                        default:
                            transportManager.Logger.Error( $"Invalid first answer from remote '{remote.Party.FullName}'." );
                            return null;
                    }
                }
                finally
                {
                    if( disposeTransport )
                    {
                        transportManager.CondemnTransport( transport );
                        transport = null;
                    }
                }
            }
            return transport;
        }

    }
}
