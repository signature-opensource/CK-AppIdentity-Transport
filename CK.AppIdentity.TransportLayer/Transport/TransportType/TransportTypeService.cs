using CK.Core;
using System.Net;
using System.Diagnostics;
using System.Net.Http.Headers;
using CK.AppIdentity.KeyManagement;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Base class for <see cref="ITransportTypeService"/> implementations.
    /// </summary>
    [CKTypeDefiner]
    public abstract class TransportTypeService : ITransportTypeService
    {
        /// <summary>
        /// Initializes a new <see cref="TransportTypeService"/>.
        /// </summary>
        protected TransportTypeService()
        {
        }

        /// <inheritdoc/>
        public abstract string AddressProtocolName { get; }

        /// <inheritdoc/>
        public abstract TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, ImmutableConfigurationSection section );

        /// <summary>
        /// Gets a default typed address if this type of transport supports it.
        /// Returns null by default.
        /// </summary>
        public virtual object? DefaultListeningAddress => null;

        /// <summary>
        /// Creates a new listener: the <paramref name="typedAddress"/> is not currently listening.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="typedAddress">The listening end point (necessarily a compatible address that has been parsed by this service).</param>
        /// <returns>The transport listener or null if it cannot be created.</returns>
        internal protected abstract TransportListener? TryCreateListener( IActivityMonitor monitor, object typedAddress );

        /// <summary>
        /// Attempts a connection to the provided <paramref name="typedAddress"/>.
        /// If connection is not possible, any exception may be thrown but preferably a null <see cref="Transport"/>
        /// should be returned and the <paramref name="logger"/> be used to log a detailed error.
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="typedAddress">The target end point (that has been successfully parsed by this service).</param>
        /// <param name="localKeys">Local key manager of this calling party.</param>
        /// <param name="remoteKeys">Remote key manager of this calling party.</param>
        /// <param name="cancellation">Cancellation token that will be signaled if the connection attempt timeout is reached.</param>
        /// <returns>A Transport or null.</returns>
        internal protected abstract Task<Transport?> TryConnectAsync( IParallelLogger logger,
                                                                      TransportTypeAddress typedAddress,
                                                                      ILocalKeys localKeys,
                                                                      IRemoteKeys remoteKeys,
                                                                      CancellationToken cancellation );
    }
}
