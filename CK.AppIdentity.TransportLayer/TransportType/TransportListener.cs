using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// A TransportListener is in charge of receiving new incoming connections.
    /// It typically is an async loop that listens to an endpoint, whatever it is, and
    /// when an incoming connexion is detected:
    /// <list type="number">
    /// <item>Creates the concrete Transport instance.</item>
    /// <item>Calls <see cref="TransportManager.OnIncomingConnection(Transport)"/>.</item>
    /// </list>
    /// A listener is bound to a set of remotes: the connection manager will accept or reject
    /// the new Transport based on this set and the <see cref="InitialMessage"/> it will receive
    /// from the remote.
    /// </summary>
    public abstract class TransportListener
    {
        readonly TransportManager _transportManager;
        readonly ITransportTypeService _transportType;
        TransportFeature[] _parties;

        /// <summary>
        /// Initializes a new TransportListener.
        /// </summary>
        /// <param name="transportManager">The TransportManager.</param>
        /// <param name="transportType">The transport type that manages this listener.</param>
        protected TransportListener( TransportManager transportManager, ITransportTypeService transportType )
        {
            _parties = Array.Empty<TransportFeature>();
            _transportManager = transportManager;
            _transportType = transportType;
        }

        /// <summary>
        /// Gets the set of remotes <see cref="TransportFeature"/> that this listener handles.
        /// This is thread safe.
        /// </summary>
        public IReadOnlyList<TransportFeature> Parties => _parties;

        internal void AddParty( TransportFeature party )
        {
            Debug.Assert( !_parties.Contains( party ) );
            Util.InterlockedAdd( ref _parties, party );
        }

        internal void RemoveParty( TransportFeature party )
        {
            Debug.Assert( _parties.Contains( party ) );
            Util.InterlockedRemove( ref _parties, party );
        }

        /// <summary>
        /// Gets the transport manager.
        /// </summary>
        public TransportManager TransportManager => _transportManager;

        /// <summary>
        /// Gets a string that describes this listener's endpoint.
        /// Description should be unique and readable.
        /// </summary>
        public abstract string EndPointDescription { get; }

        /// <summary>
        /// Gets whether this listener listens on the <paramref name="address"/>.
        /// </summary>
        /// <param name="address">The address to test.</param>
        /// <returns>True if this listener listens to this address, false otherwise.</returns>
        public bool IsListeningAddress( TransportTypeAddress address )
        {
            Throw.CheckNotNullArgument( address );
            if( address.Type != _transportType ) return false;
            return IsListeningAddress( address.TypedAddress );
        }

        /// <summary>
        /// Implements <see cref="IsListeningAddress(TransportTypeAddress)"/> on the typed address.
        /// </summary>
        /// <param name="typedAddress">The typed address to test.</param>
        /// <returns>True if this listener listens to this address, false otherwise.</returns>
        internal protected abstract bool IsListeningAddress( object typedAddress );
    }
}
