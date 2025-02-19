using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Handles calls to <see cref="TransportTypeService.TryConnectToAsync(IActivityLogger, IRemoteParty, object, CancellationToken)"/>.
/// This BackTask is always retried until a valid (tested) outgoing connection is obtained or the remote party is destroyed or switched off.
/// </summary>
sealed class OutgoingConnectionBackTask : BackTask<TransportManager>
{
    TransportFeature? _remote;
    // No timeout on this cts: no Dispose required.
    CancellationTokenSource? _cts;
    // The run taks returns the retry delay.
    Task<int>? _result;
    // Current start or restart count.
    int _tryConnectCount;
    // Current start time.
    DateTime _startTime;
    // Transition to true when cancelling because remote.IsOff.
    bool _offlineDecision;

    public override void OnDestroy( IActivityMonitor monitor )
    {
        Throw.DebugAssert( _remote != null );
        if( IsStarted && !_cts.IsCancellationRequested )
        {
            CancelOperation( monitor, offline: true );
        }
    }

    [MemberNotNullWhen( true, nameof( _result ), nameof( _cts ), nameof( _remote ) )]
    bool IsStarted
    {
        get
        {
            Throw.DebugAssert( _remote != null );
            Throw.DebugAssert( "_result != null => _cts != null", _result == null || _cts != null );
            return _result != null;
        }
    }

    public override void Check( IActivityMonitor monitor, int previousCheckDelay )
    {
        Throw.DebugAssert( _remote != null && _remote.TargetAddress != null );
        if( IsStarted )
        {
            // Handles a completed result first.
            if( _result.IsCompleted )
            {
                if( _result.IsCompletedSuccessfully )
                {
                    // Successful completion: either the new transport has been provided to the TransportFeature
                    // by TryConnectToAsync or we have a retry delay.
#pragma warning disable VSTHRD002 // We have checked that _result.IsCompletedSuccessfully is true. 
                    int delay = _result.Result;
#pragma warning restore VSTHRD002 // Avoid problematic synchronous waits
                    if( delay > 0 )
                    {
                        if( !_offlineDecision ) NextCheckDelay = delay;
                        else monitor.Debug( $"Forgetting the retry in {delay} seconds since '{_remote.Party}' is offline." );
                    }
                    // Else (delay is 0), we are done, let this BackTask be reset.
                }
                else
                {
                    // We have an error or have been canceled..
                    // The error is typically a parsing error of an incoming message, we increase the retry time.
                    Throw.DebugAssert( _tryConnectCount > 0 );
                    int retryDelay = Math.Min( _tryConnectCount, 30 );
                    if( _result.IsFaulted )
                    {
                        monitor.Error( $"OutgoingConnectionBackTask #{GetHashCode()}: Unhandled error while connecting to '{_remote.Party}'. Retrying in {retryDelay} seconds.", _result.Exception );
                    }
                    else
                    {
                        Throw.DebugAssert( _result.IsCanceled );
                        if( !_cts.IsCancellationRequested )
                        {
                            // Cancellation is not by us and that is weird!
                            monitor.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                           $"OutgoingConnectionBackTask #{GetHashCode()}: Unexpected cancellation while connecting to '{_remote.Party}'. Retrying in {retryDelay} seconds." );
                        }
                        // Else, regular case: cancellation belongs to us, it is a timeout or a offline decision.
                        // On timeout the delay is the same as for an unexpected error.
                    }
                    if( !_offlineDecision ) NextCheckDelay = retryDelay;
                }
                // Forget the completed result.
                _result = null;
                return;
            }
            // If CancelOperation signaled our CTS and the task is still alive, this is weird.
            if( _cts.IsCancellationRequested )
            {
                monitor.Warn( ActivityMonitor.Tags.ToBeInvestigated,
                              $"OutgoingConnectionBackTask #{GetHashCode()}: Failure to complete cancellation of for Remote '{_remote.Party}'." +
                              $" Forgetting the current Task." );
                _result = null;
                if( !_offlineDecision ) NextCheckDelay = 30;
                return;
            }
            // If remote became off, we cancel this back task. Retrying is in 1 tick: the task should be canceled then.
            if( _remote.IsOff )
            {
                CancelOperation( monitor, offline: true );
                return;
            }
            // The attempt is still running. If it takes more than NegotiationTimeout seconds, cancel it.
            var delta = DateTime.UtcNow - _startTime;
            if( delta > TimeSpan.FromMilliseconds( TransportManager.NegotiationTimeout ) )
            {
                monitor.Warn( $"OutgoingConnectionBackTask #{GetHashCode()}: Timeout ({(int)delta.TotalMilliseconds} ms) while connecting to remote '{_remote.Party}'. Reseting in 1 second." );
                CancelOperation( monitor, false );
                return;
            }
            // Check again asap.
            NextCheckDelay = 1;
        }
        else
        {
            // Delayed start: check that the remote is alive before starting.
            if( !_remote.IsOff ) StartTryConnect();
            return;
        }
    }

    void CancelOperation( IActivityMonitor monitor, bool offline )
    {
        Throw.DebugAssert( IsStarted && !_cts.IsCancellationRequested );

        if( offline )
        {
            _offlineDecision = true;
            monitor.Info( $"OutgoingConnectionBackTask #{GetHashCode()}: Remote '{_remote.Party}' is off line. Reseting in 1 second." );
        }
        // We signal the cancelation but wait one tick to handle it.
        _cts.Cancel();
        // This avoids any UnobservedTaskException on the result if cancellation fails to be honored in 1 tick.
        _ = _result.ContinueWith( t => t.Exception?.Handle( static _ => true ),
                                  CancellationToken.None,
                                  TaskContinuationOptions.ExecuteSynchronously,
                                  TaskScheduler.Default );
        NextCheckDelay = 1;
    }

    public void OnInitialize( TransportFeature remote, int startDelay )
    {
        Throw.DebugAssert( remote != null && remote.TargetAddress != null && _remote == null );
        _remote = remote;
        _tryConnectCount = 0;
        if( startDelay == 0 )
        {
            // Immediate start.
            StartTryConnect();
        }
        else
        {
            NextCheckDelay = startDelay;
        }
    }

    void StartTryConnect()
    {
        Throw.DebugAssert( _remote != null );
        // Reuse the same CTS if possible.
        if( _cts == null || !_cts.TryReset() )
        {
            _cts = new CancellationTokenSource();
        }
        _startTime = DateTime.UtcNow;
        _result = TryConnectToAsync( TaskManager.Host, _remote, _cts, _tryConnectCount++ );
#pragma warning disable VSTHRD002 // Avoid problematic synchronous waits
        NextCheckDelay = _result.IsCompletedSuccessfully
                            ? _result.Result
                            : 1;
#pragma warning restore VSTHRD002 // Avoid problematic synchronous waits
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
        Throw.DebugAssert( "Feature initialization is done.", remote.OutgoingInitialMessage != null );
        Throw.DebugAssert( remote.TargetAddress != null );

        Transport? transport;
        try
        {
            transport = await remote.TargetAddress.Type.TryConnectAsync( transportManager.Logger,
                                                                         remote.TargetAddress,
                                                                         remote.RemoteKeys,
                                                                         cancellation.Token );
            if( transport == null )
            {
                return OnInitialFailure( transportManager.Logger,
                                         remote,
                                         currentTryCount,
                                         $"Unable to open connection to",
                                         exception: null );
            }
        }
        catch( Exception ex )
        {
            return OnInitialFailure( transportManager.Logger,
                                     remote,
                                     currentTryCount,
                                     $"While creating Transport to",
                                     ex );
        }

        Throw.DebugAssert( transport.RemoteKeys == remote.RemoteKeys );
        IncomingMessage? firstAnswer = null;
        transport.SetCancellationSource( cancellation );
        transportManager.Logger.Debug( $"Created new Outgoing transport #{transport.GetHashCode()} for '{remote.Party}' to '{transport.RemoteEndPointDescription}'." );
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
            if( !firstAnswer.IsValid || firstAnswer == IncomingMessage.Empty || firstAnswer == IncomingMessage.EmptyAck )
            {
                return OnInitialFailure( transportManager.Logger,
                                                  remote,
                                                  currentTryCount,
                                                  firstAnswer == IncomingMessage.Canceled
                                                     ? "Canceled received from"
                                                     : "Empty message received from",
                                                  exception: null );
            }
            var head = firstAnswer.Message.First;
            Throw.DebugAssert( "The message is not empty (handled above).", head.Length > 0 );
            switch( head.Span[0] )
            {
                case ZeroProtocol.DNegoFinalFailureMessage:
                    {
                        // Weird case: the remote couldn't verify our signature or the nonce check failed.
                        // We don't have any other available data.
                        transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                        $"The remote '{remote.Party}' was unable to verify our signature or the nonce check failed. Retrying in 10 seconds." );
                        return 10;
                    }
                case ZeroProtocol.DNegoRejectRemote:
                    {
                        RemoteIdentityKey? trustedIdentity = remote.RemoteKeys.TrustedIdentity;
                        ZeroProtocol.ReadRejectRemoteReplyMessage( firstAnswer,
                                                                    sentNonce.Value,
                                                                    trustedIdentity,
                                                                    out bool nonceFailure,
                                                                    out ZeroProtocol.ConfigurationOrTrustIssue pIssue,
                                                                    out TimeSpan? clockOffset,
                                                                    out string? enlistUrl,
                                                                    out RemoteIdentityKeyData? currentKeyData,
                                                                    out bool foundTrustedKey,
                                                                    out RemoteIdentityKey? currentKey,
                                                                    out bool signatureVerified );
                        // We have data but if the nonce we sent is not the one we have in reply, this is a serious issue.
                        if( nonceFailure )
                        {
                            transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                           $"The remote '{remote.Party}' sent an invalid Nonce. Retrying in 30 seconds." );
                            return 30;
                        }
                        // If there is no remote key data, we are totally unknown to the target or the transport is disallowed (the message is not
                        // signed in this case because the remote system must not pick a Localkeys provider at random among its root and
                        // potential TenantDomains). And vice versa.
                        // We check a Protocol error here.
                        if( (currentKeyData == null) != (enlistUrl == null && pIssue is ZeroProtocol.ConfigurationOrTrustIssue.Unknwon
                                                                                        or ZeroProtocol.ConfigurationOrTrustIssue.DisallowedTransport) )
                        {
                            // Weird: The only possible issues when the message is not signed are Unknwon and DisallowedTransport
                            //        and enlistUrl must be null.
                            transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                           $"Protocol error from '{remote.Party}'. Issue='{pIssue}' (must be Unknwon or DisallowedTransport), " +
                                                           $"EnlistUrl='{enlistUrl}' (must be null). Retrying in 30 seconds." );
                            return 30;
                        }
                        // Check the signature if it must be signed.
                        if( currentKeyData != null && !signatureVerified )
                        {
                            // Weird: the sent signatures cannot be verified.
                            transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                                           $"Unable to verify the signature's reply message from '{remote.Party}'. Retrying in 30 seconds." );
                            return 30;
                        }
                        // From now on we'll always retry in 5 seconds.
                        transportManager.Logger.Warn( $"The remote '{remote.Party}' listener rejected us. Issue='{pIssue}', EnlistUrl='{enlistUrl}'. " +
                                                      $"Retrying in 5 seconds." );
                        PeeringIssueKind issue;
                        // Handles the no signature case.
                        if( currentKeyData == null )
                        {
                            Throw.DebugAssert( !signatureVerified );
                            issue = pIssue switch
                            {
                                ZeroProtocol.ConfigurationOrTrustIssue.Unknwon => PeeringIssueKind.RequiresRemoteCreation,
                                ZeroProtocol.ConfigurationOrTrustIssue.DisallowedTransport => PeeringIssueKind.RemoteDisallowedTransport,
                                _ => Throw.NotSupportedException<PeeringIssueKind>()
                            };
                            transportManager.OnRemoteConfigurationOrTrustIssue( remote, issue, null, enlistUrl, null );
                            return 5;
                        }
                        // Signature is fine. We update our TrustedIdentity.
                        remote.RemoteKeys.OnReadIdentityKeys( transportManager.Logger, foundTrustedKey, currentKeyData, currentKey );
                        // Thanks to the InitialMessage.RemoteTrustInfo, the remote has detected that we won't be able to trust him:
                        // we must provide him our EnlistUrl (even if it is null).
                        if( pIssue is ZeroProtocol.ConfigurationOrTrustIssue.ListenerRequiresLocalApproval
                                      or ZeroProtocol.ConfigurationOrTrustIssue.RequiresBothApproval )
                        {
                            // This is our EnlistUrl for him. (Note that the second parameter is unused).
                            var hisEnlistUrl = transportManager.GetEnlistRemoteUrl( remote.Party, string.Empty );
                            // We don't care if this is not sent.
                            Throw.DebugAssert( remote.RemoteKeys == transport.RemoteKeys );
                            await ZeroProtocol.SendRequiredEnlistUrlMessageAsync( transport, hisEnlistUrl, sentNonce.Value );
                        }

                        issue = pIssue switch
                        {
                            ZeroProtocol.ConfigurationOrTrustIssue.InvalidClockOffset => PeeringIssueKind.InvalidClockOffset,
                            ZeroProtocol.ConfigurationOrTrustIssue.InitiatorConflict => PeeringIssueKind.InitiatorConflict,
                            ZeroProtocol.ConfigurationOrTrustIssue.UnsupportedTransport => PeeringIssueKind.RemoteUnsupportedTransport,
                            ZeroProtocol.ConfigurationOrTrustIssue.ListenerRequiresLocalApproval => PeeringIssueKind.RequiresRemoteApproval,
                            ZeroProtocol.ConfigurationOrTrustIssue.ListenerRequiresRemoteApproval => PeeringIssueKind.RequiresLocalApproval,
                            ZeroProtocol.ConfigurationOrTrustIssue.RequiresBothApproval => PeeringIssueKind.RequiresBothApproval,
                            // Unknwon and DisallowedTransport are already handled.
                            ZeroProtocol.ConfigurationOrTrustIssue.Unknwon => Throw.Exception<PeeringIssueKind>( pIssue.ToString() ),
                            ZeroProtocol.ConfigurationOrTrustIssue.DisallowedTransport => Throw.Exception<PeeringIssueKind>( pIssue.ToString() ),
                            _ => Throw.NotSupportedException<PeeringIssueKind>( pIssue.ToString() )
                        };
                        var usefulRemoteKey = issue is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval
                                                ? currentKeyData
                                                : null;
                        transportManager.OnRemoteConfigurationOrTrustIssue( remote, issue, clockOffset, enlistUrl, usefulRemoteKey );
                        return 5;
                    }
                case ZeroProtocol.DNegoOffRemote:
                    {
                        int retryDelay;
                        if( !ZeroProtocol.ReadOffRemoteMessage( transportManager.Logger,
                                                                remote,
                                                                firstAnswer,
                                                                sentNonce.Value,
                                                                out var clockOffset,
                                                                out var offMessage ) )
                        {
                            // The nonce or the verification failed (this has been logged), retries in 30 seconds.
                            retryDelay = 30;
                        }
                        else
                        {
                            if( offMessage is GoodbyeMessage.SwitchedOff sOff )
                            {
                                retryDelay = HandleRemoteSwitchedOff( remote, clockOffset, sOff );
                            }
                            else
                            {
                                // PartyDestroyed and ApplicationIdentityShutdown: this can be transient (restart of the application
                                // or suppresion of a dynamic party to add it back with a different configuration).
                                // We don't switch of our remote, we just emit an issue.
                                retryDelay = 5;
                            }
                            // If the remote is switched off because of us, don't emit the issue.
                            if( offMessage != null )
                            {
                                transportManager.OnRemoteSwitchedOffIssue( remote, offMessage );
                            }
                        }
                        if( retryDelay != 0 ) transportManager.Logger.Trace( $"Retrying in {retryDelay} seconds." );
                        return retryDelay;
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
                        // Sends the initiator DNegoFinalSuccessMessage.
                        if( await ZeroProtocol.SendFinalSuccessMessageAsync( transport, remote, sentNonce.Value, finalClockOffset ).ConfigureAwait( false ) )
                        {
                            // Accepts the transport.
                            killTransport = false;
                            transportManager.NewValidTransport( remote.Party, transport, protocolMap, finalClockOffset, evictionMessage: null );
                            // Successful SendFinalMessageAsync: the BackTask will be reset).
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
                            transportManager.OnRemoteDisallowEvictionIssue( remote );
                            return 20;
                        }
                        transportManager.Logger.Info( "Retrying in 30 seconds." );
                        return 30;
                    }
                case ZeroProtocol.DNegoMissingProtocols:
                    {
                        if( !ZeroProtocol.TryReadMissingProtocolsMessage( transportManager.Logger,
                                                                          firstAnswer,
                                                                          sentNonce.Value,
                                                                          remote,
                                                                          out var localMissing,
                                                                          out var remoteMissing ) )
                        {
                            transportManager.Logger.Info( "Retrying in 30 seconds." );
                            return 30;
                        }
                        transportManager.Logger.Error( $"Missing protocols for remote '{remote.Party}':{Environment.NewLine}" +
                                                       $"We (initiator) miss: {localMissing?.Concatenate()}{Environment.NewLine}" +
                                                       $"He (listener) misses: {remoteMissing?.Concatenate()}" );
                        transportManager.OnMissingProtocolsIssues( null, remote, localMissing, remoteMissing );
                        return 30;
                    }
                default:
                    return OnInitialFailure( transportManager.Logger,
                                                      remote,
                                                      currentTryCount,
                                                      $"Invalid first message discriminator '{head.Span[0]}' from",
                                                      exception: null );
            }
        }
        finally
        {
            firstAnswer?.Dispose();
            if( killTransport )
            {
                transportManager.Logger.Debug( $"Killing useless Outgoing transport #{transport.GetHashCode()}." );
                // This outgoing transport is useless, we don't want the transport manager to initialize another
                // back task: this one is enough.
                transportManager.KillTransport( transport, int.MaxValue );
            }
        }

        static int OnInitialFailure( IParallelLogger logger, TransportFeature remote, int currentTryCount, string msg, Exception? exception )
        {
            if( remote.IsOff )
            {
                logger.Error( $"{msg} '{remote.Party}' at '{remote.TargetAddress}'. Transport is switched off. Give up.", exception );
                return 0;
            }
            var retryDelay = Math.Min( currentTryCount + 1, 5 );
            logger.Error( $"{msg} '{remote.Party}' at '{remote.TargetAddress}'. Retrying in {retryDelay} seconds.", exception );
            return retryDelay;
        }
    }

    /// <summary>
    /// Handles a remote received <see cref="GoodbyeMessage.SwitchedOff"/> message by computing the retry delay in seconds (heartbeats)
    /// and if the <see cref="GoodbyeMessage.SwitchedOff.ExpectedAvailableTime"/> is <see cref="Util.UtcMaxValue"/> by switching
    /// off our <paramref name="remote"/> with the message.
    /// <para>
    /// Used by <see cref="TransportController.Receive0Message(IActivityMonitor, IncomingMessage)"/> and by the <see cref="OutgoingConnectionBackTask"/>
    /// when a <see cref="ZeroProtocol.DNegoOffRemote"/> is received.
    /// </para>
    /// </summary>
    /// <param name="remote">The remote feature.</param>
    /// <param name="clockOffset">The clock offset.</param>
    /// <param name="offMessage">The swithed off message.</param>
    /// <returns>The retry delay. 0 for no retry.</returns>
    internal static int HandleRemoteSwitchedOff( TransportFeature remote, TimeSpan clockOffset, GoodbyeMessage.SwitchedOff offMessage )
    {
        int retryDelay;
        if( offMessage.ExpectedAvailableTime.HasValue )
        {
            var t = offMessage.ExpectedAvailableTime.Value;
            if( t == Util.UtcMaxValue )
            {
                // We are done!
                // Switch off our remote: this is what year 9999 means.
                remote.RemoteSwitchedOff( offMessage );
                // And stop retrying!
                retryDelay = 0;
            }
            else
            {
                var delta = t - remote.Party.ApplicationIdentityService.SystemClock.UtcNow;
                retryDelay = Math.Max( (int)(delta + clockOffset).TotalSeconds, 5 );
            }
        }
        else
        {
            retryDelay = 5;
        }
        return retryDelay;
    }
}
