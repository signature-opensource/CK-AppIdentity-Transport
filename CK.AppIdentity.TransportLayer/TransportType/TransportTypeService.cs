using CK.Core;
using System.Net;
using System.Diagnostics;

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
        /// Creates a new listener: the <paramref name="endPoint"/> is not currently listening.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="transportManager">The transport manager.</param>
        /// <param name="typedAddress">The listening end point (necessarily a compatible address that has been parsed by this service).</param>
        /// <param name="remote">The first remote party that needs this listener.</param>
        /// <returns>The transport listener or null if it cannot be created.</returns>
        protected abstract TransportListener? TryCreateListener( IActivityMonitor monitor, TransportManager transportManager, object typedAddress, IRemoteParty remote );

        /// <summary>
        /// Ensures that a listener is setup on the <paramref name="endPoint"/> and registers a remote that needs it.
        /// </summary>
        /// <param name="monitor">The monitor to signal errors.</param>
        /// <param name="transportManager">The transport manager.</param>
        /// <param name="endPoint">The listening address.</param>
        /// <param name="remote">The remote that requires this listener.</param>
        /// <returns>True on success, false otherwise.</returns>
        internal bool RegisterListenerParty( IActivityMonitor monitor, TransportManager transportManager, TransportTypeAddress endPoint, IRemoteParty remote )
        {
            Debug.Assert( endPoint.Type == this );
            Debug.Assert( transportManager.IsInApplicationIdentityLoop( monitor ) );

            foreach( var exists in _listeners )
            {
                if( exists.IsListeningAddress( endPoint.TypedAddress ) )
                {
                    exists.AddParty( remote );
                    return true;
                }
            }
            var l = TryCreateListener( monitor, transportManager, endPoint.TypedAddress, remote );
            if( l == null ) return false;
            _listeners.Add( l );
            return true;
        }

        /// <summary>
        /// Attempts a connection to the provided <paramref name="typedAddress"/>.
        /// If connection is not possible, any exception may be thrown but preferably  a null <see cref="Transport"/>
        /// should be returned and the <paramref name="logger"/> be used to log a detailed error.
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="typedAddress">The target end point (necessarily a compatible address that has been parsed by this service).</param>
        /// <param name="cancellation">Cancellation token that will be signaled if the connection attempt timeout is reached.</param>
        /// <returns>A Transport or null.</returns>
        internal protected abstract Task<Transport?> TryConnectAsync( IActivityLogger logger, object typedAddress, CancellationToken cancellation );

    }
}
