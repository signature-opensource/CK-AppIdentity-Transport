using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// A TransportListener is in charge of receiving new incoming connections.
    /// It typically is an async loop that listens to an endpoint, whatever it is, and
    /// when an incoming connexion is detected:
    /// <list type="number">
    /// <item>Creates the concrete Transport instance.</item>
    /// <item>Calls <see cref="OnIncomingTransport(Transport)"/>.</item>
    /// </list>
    /// A listener is bound to a set of remote parties: the connection manager will accept
    /// or reject the new Transport based on this set and the initial message it will
    /// receive from the remote.
    /// </summary>
    public abstract class TransportListener
    {
        [AllowNull]
        internal TransportManager _transportManager;
        readonly ITransportTypeService _transportType;
        TransportFeature[] _parties;

        /// <summary>
        /// Initializes a new TransportListener.
        /// </summary>
        /// <param name="transportType">The transport type that manages this listener.</param>
        protected TransportListener( ITransportTypeService transportType )
        {
            Throw.CheckNotNullArgument( transportType );
            _parties = Array.Empty<TransportFeature>();
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
        /// Gets the <see cref="IParallelLogger"/> to use.
        /// </summary>
        protected IParallelLogger Logger => _transportManager.Logger;

        /// <summary>
        /// Must be called when a new <see cref="Transport"/> is connected.
        /// </summary>
        /// <param name="transport">The new transport.</param>
        protected void OnIncomingTransport( Transport transport )
        {
            Throw.CheckNotNullArgument( transport );
            _transportManager.IncomingTransport( transport );
        }

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

        /// <summary>
        /// Disposes this listener: any resources must be released.
        /// </summary>
        internal protected abstract ValueTask DisposeAsync( IActivityMonitor monitor );

        /// <summary>
        /// Overridden to return this type, the <see cref="EndPointDescription"/> and the number
        /// of parties.
        /// </summary>
        /// <returns></returns>
        public sealed override string ToString() => $"{GetType().Name} - {EndPointDescription} ({_parties.Length} parties)";
    }
}
