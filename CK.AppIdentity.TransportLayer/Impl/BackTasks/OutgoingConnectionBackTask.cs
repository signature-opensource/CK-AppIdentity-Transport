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
        IRemoteParty? _remoteParty;
        TransportTypeAddress? _target;
        private int _setupTick;
        CancellationTokenSource? _cts;
        Task<Transport?>? _result;
        int _tryCancelCount;
        int _tryCount;

        public override void Check( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remoteParty != null && _target != null && _result != null && _cts != null );
            if( _remoteParty.IsDestroyed )
            {
                if( _tryCancelCount++ == 0 )
                {
                    monitor.Trace( $"Remote '{_remoteParty.FullName}' destroyed. Stopping its OutgoingConnectionBackTask." );
                }
                if( !CancelOperation( monitor, transportManager ) )
                {
                    Retry( 1 );
                }
                // If the CancelOperation succeeded, let this BackTask be reset.
            }
            else if( _result.IsCompleted )
            {
                if( _result.IsCompletedSuccessfully )
                {
                    if( _result.Result != null )
                    {
                        // Provide the new transport to the TransportFeature and we are done.
                        var channel = _remoteParty.GetRequiredFeature<TransportFeature>();
                        channel.OnNewTransport( monitor, _result.Result );
                        // Let this BackTask be reset.
                    }
                    else
                    {
                        // No transport, retrying.
                        Setup( transportManager, _remoteParty, _target );
                        Retry( 1 );
                    }
                }
                else
                {
                    // We have an error or have been canceled... (cancellation is not by us and that is weird!, but this is the same: we must retry).
                    monitor.Warn( $"Failed to connect to '{_remoteParty.FullName}' (try n°{++_tryCount}). Retrying.", _result.Exception );
                    Setup( transportManager, _remoteParty, _target );
                    Retry( 1 );
                }
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
                            monitor.Error( $"Connection to '{_remoteParty.FullName}' is blocking and the operation cannot be canceled! Forgetting it and retrying." );
                            Setup( transportManager, _remoteParty, _target );
                        }
                    }
                }
                Retry( 1 );
            }
        }

        bool CancelOperation( IActivityMonitor monitor, TransportManager transportManager )
        {
            Debug.Assert( _remoteParty != null && _result != null && _cts != null );

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

        public void Setup( TransportManager transportManager, IRemoteParty remoteParty, TransportTypeAddress target )
        {
            Debug.Assert( remoteParty != null && target != null && remoteParty != null );
            _cts ??= new CancellationTokenSource();
            _result = target.Type.TryConnectToAsync( transportManager.Logger, remoteParty, target.TypedAddress, _cts.Token );
            _remoteParty = remoteParty;
            _target = target;
            _setupTick = CurrentTick;
        }

        public override void Reset()
        {
            _remoteParty = null;
            _target = null;
            _tryCancelCount = 0;
            _tryCount = 0;
            if( _cts != null && !_cts.TryReset() ) _cts = null;
        }
    }
}
