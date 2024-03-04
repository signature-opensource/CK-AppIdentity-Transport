using CK.Core;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

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
        // This is set right after the instantiation to avoid a constructor parameter
        // with which the developper must not interact with.
        internal TransportManager _transportManager;
        readonly ITransportTypeService _transportType;
        TransportFeature[] _parties;
        // Life and death of a listener is based on a ref count.
        int _refCount;

        /// <summary>
        /// Initializes a new TransportListener.
        /// </summary>
        /// <param name="opaqueHandle">Must be the handle from <see cref="TransportTypeService.TryCreateListener(IActivityMonitor, object, object)"/>.</param>
        /// <param name="transportType">The transport type that manages this listener.</param>
        protected TransportListener( object opaqueHandle, ITransportTypeService transportType )
        {
            Throw.CheckNotNullArgument( transportType );
            if( opaqueHandle is not TransportManager m )
            {
                Throw.ArgumentException( nameof( opaqueHandle ) );
                return;
            }
            _transportManager = m;
            _parties = Array.Empty<TransportFeature>();
            _transportType = transportType;
            _refCount = 1;
        }

        /// <summary>
        /// Gets the set of remotes <see cref="TransportFeature"/> that this listener handles.
        /// This is thread safe.
        /// </summary>
        public IReadOnlyList<TransportFeature> Parties => _parties;

        /// <summary>
        /// Adds a remote party that is bound to this listener.
        /// This is called when parties are created from the ApplicationIdentityService's agent loop:
        /// RemoveParty is also called from the ApplicationIdentityService's agent: we don't need synchronization here.
        /// </summary>
        /// <param name="monitor">The Application Identity monitor agent.</param>
        /// <param name="party">The valid party for this listener.</param>
        internal void AddParty( IActivityMonitor monitor, TransportFeature party )
        {
            Throw.DebugAssert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            Throw.DebugAssert( !_parties.Contains( party ) );
            var newArray = new TransportFeature[_parties.Length + 1];
            Array.Copy( _parties, 0, newArray, 0, _parties.Length );
            newArray[_parties.Length] = party;
            _parties = newArray;
        }

        /// <summary>
        /// Removes a remote party that is bound to this listener.
        /// This is called by the ApplicationIdentityService's agent when tearing down the remote.
        /// </summary>
        /// <param name="monitor">The Application Identity monitor agent.</param>
        /// <param name="party">The destroyed party.</param>
        internal void RemoveParty( IActivityMonitor monitor, TransportFeature party )
        {
            Throw.DebugAssert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            int num = Array.IndexOf( _parties, party );
            Throw.DebugAssert( num >= 0 );
            var newArray = new TransportFeature[_parties.Length - 1];
            Array.Copy( _parties, 0, newArray, 0, num );
            Array.Copy( _parties, num + 1, newArray, num, newArray.Length - num );
            _parties = newArray;
        }

        /// <summary>
        /// Increments the reference count. This doesn't need to be Interlocked because it is
        /// called only from the ApplicationIdentityService's agent when party are
        /// created.
        /// </summary>
        internal void AddRef( IActivityMonitor monitor )
        {
            Throw.DebugAssert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            ++_refCount;
            monitor.Debug( $"Added reference to Listener '{ToString()}' (RefCount = {_refCount})." );
        }

        /// <summary>
        /// Release a reference. This doesn't need to be Interlocked because it is
        /// called only from the ApplicationIdentityService's agent when party are
        /// destroyed.
        /// </summary>
        internal async ValueTask ReleaseAsync( IActivityMonitor monitor )
        {
            Throw.DebugAssert( _transportManager.IsInApplicationIdentityLoop( monitor ) );
            --_refCount;
            monitor.Debug( $"Removed reference to Listener '{ToString()}' (RefCount = {_refCount})." );
            if( _refCount == 0 )
            {
                using( monitor.OpenInfo( $"Disposing listener '{ToString()}'." ) )
                {
                    try
                    {
                        await DisposeAsync( monitor );
                    }
                    catch( Exception ex )
                    {
                        monitor.Error( $"While disposing '{ToString()}'.", ex );
                    }
                    _transportManager.OnListenerDisposed( monitor, this );
                }
            }
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
            _transportManager.IncomingTransport( transport, _transportManager.SystemClock.UtcNow );
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
