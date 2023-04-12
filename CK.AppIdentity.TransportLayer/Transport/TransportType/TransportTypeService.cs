using CK.Core;
using System.Net;
using System.Diagnostics;
using System.Net.Http.Headers;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Base class for <see cref="ITransportTypeService"/> implementations.
    /// </summary>
    public abstract class TransportTypeService : ITransportTypeService
    {
        readonly List<TransportListener> _listeners;

        /// <summary>
        /// Initializes a new <see cref="TransportTypeService"/>.
        /// </summary>
        protected TransportTypeService()
        {
            _listeners = new List<TransportListener>();
        }

        /// <inheritdoc/>
        public abstract string AddressProtocolName { get; }

        /// <inheritdoc/>
        public abstract TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, string configurationPath, string? configurationKey );

        /// <summary>
        /// Creates a new listener: the <paramref name="typedAddress"/> is not currently listening.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="typedAddress">The listening end point (necessarily a compatible address that has been parsed by this service).</param>
        /// <returns>The transport listener or null if it cannot be created.</returns>
        protected abstract TransportListener? TryCreateListener( IActivityMonitor monitor, object typedAddress );

        /// <summary>
        /// Ensures that a listener is setup on the <paramref name="endPoint"/>.
        /// The listener should be as ready as possible to handle incoming connections.
        /// </summary>
        /// <param name="monitor">The monitor to signal errors.</param>
        /// <param name="transportManager">The transport manager.</param>
        /// <param name="endPoint">The listening address.</param>
        /// <returns>The listener on success, null otherwise.</returns>
        internal TransportListener? TryEnsureListener( IActivityMonitor monitor, TransportManager transportManager, TransportTypeAddress endPoint )
        {
            Debug.Assert( endPoint.Type == this );
            Debug.Assert( transportManager.IsInApplicationIdentityLoop( monitor ) );

            foreach( var exists in _listeners )
            {
                if( exists.IsListeningAddress( endPoint.TypedAddress ) )
                {
                    return exists;
                }
            }
            var l = TryCreateListener( monitor, endPoint.TypedAddress );
            if( l != null )
            {
                l._transportManager = transportManager;
                _listeners.Add( l );
            }
            return l;
        }

        internal async Task<Transport?> TryConnectToAsync( TransportManager transportManager, TransportFeature remote, TransportTypeAddress typedAddress, CancellationTokenSource cancellation )
        {
            Debug.Assert( remote.OutgoingInitialMessage != null, "Feature initialization is done." );
            var transport = await TryConnectAsync( transportManager.Logger, typedAddress, cancellation.Token );
            if( transport != null )
            {
                transport.SetCancellationSource( cancellation );
                bool disposeTransport = true;
                try
                {
                    // The CurrentVersion is necessarily supported. If this fails, it's because of a cancellation.
                    if( !await ZeroProtocol.SendInitialMessageAsync( remote, transport, ZeroProtocol.CurrentVersion ) )
                    {
                        // If we are canceled, let the finally condemn the new transport.
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
                        case 0:
                            {
                                // UnknownRemoteReply
                                string? userAcceptUri = ZeroProtocol.ReadUnknownRemoteReplyMessageAsync( firstAnswer );
                                transportManager.Logger.Warn( $"The remote '{remote.Party.FullName}' doesn't know us. UserAcceptUri='{userAcceptUri}'." );
                                if( userAcceptUri != null )
                                {
                                    // TODO:
                                    // transportManager.InformUserAcceptUri( remote, userAcceptUri );
                                }
                                return null;
                            }
                        case 1:
                            // DowngradeProtocolReplyMessage
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
                        case 2:
                            {
                                // AcceptedMessage
                                var protocolMap = ZeroProtocol.TryReadAcceptedMessage( transportManager.Logger, firstAnswer, remote );
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
                        case 3:
                            {
                                // MissingProtocolsMessage
                                var missingProtocols = ZeroProtocol.ReadMissingProtocolsMessage( transportManager.Logger, firstAnswer, remote );
                                if( missingProtocols == null )
                                {
                                    return null;
                                }
                                transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' expects protocols: {missingProtocols.Concatenate()}." );
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


        /// <summary>
        /// Attempts a connection to the provided <paramref name="typedAddress"/>.
        /// If connection is not possible, any exception may be thrown but preferably a null <see cref="Transport"/>
        /// should be returned and the <paramref name="logger"/> be used to log a detailed error.
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="typedAddress">The target end point (necessarily an address that has been parsed by this service).</param>
        /// <param name="cancellation">Cancellation token that will be signaled if the connection attempt timeout is reached.</param>
        /// <returns>A Transport or null.</returns>
        protected abstract Task<Transport?> TryConnectAsync( IActivityLogger logger, TransportTypeAddress typedAddress, CancellationToken cancellation );

    }
}
