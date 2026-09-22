using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

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
    /// Gets how long an incoming connection that has authenticated nothing may be worked on before
    /// it is dropped.
    /// <para>
    /// A listener whose accept does more than create an object — a TLS handshake, say — must enforce
    /// this itself, because that work happens before <see cref="OnIncomingTransport"/> and therefore
    /// before the back task that enforces it exists. Such a listener must compute ONE deadline when
    /// the connection arrives and carry it through both phases: starting a fresh timer at each stage
    /// lets an unauthenticated peer hold a slot for twice this, which the concurrency cap of
    /// <see cref="TransportManagerFeature.MaxConcurrentNegotiation"/> silently assumes it cannot.
    /// </para>
    /// <para>
    /// It is a constant and is not reachable from configuration, unlike the outgoing budget
    /// (<see cref="TransportFeature.OutgoingNegotiationTimeout"/>) which is per remote. Per remote is
    /// not merely undesirable here, it is unavailable: which remote this is arrives inside the very
    /// exchange being timed. It is also the number an attacker would most like raised.
    /// </para>
    /// </summary>
    protected static TimeSpan IncomingNegotiationTimeout => TimeSpan.FromMilliseconds( TransportManager.IncomingNegotiationTimeout );

    /// <summary>
    /// Gets the identity keys of the application itself.
    /// <para>
    /// A listener is shared by address, not owned by a party: <c>TryEnsureListener</c> returns an
    /// existing listener for the same endpoint, so the parties of <see cref="Parties"/> may belong to
    /// several different local parties. A transport that must present a credential of its own
    /// therefore cannot derive it from "the" local party — there is not one — and uses the
    /// application's own identity, which is the one thing a listener unambiguously belongs to.
    /// </para>
    /// </summary>
    protected ILocalKeys LocalKeys => _transportManager.ApplicationIdentityAgent
                                                       .ApplicationIdentityService
                                                       .GetRequiredFeature<ILocalKeys>();

    /// <summary>
    /// Must be called when a new <see cref="Transport"/> is connected.
    /// <para>
    /// When false is returned the connection is refused by admission control (too many negotiations
    /// in flight, see <see cref="TransportManagerFeature.MaxConcurrentNegotiation"/>) and nothing has
    /// been queued for it: the caller must close the underlying resource itself. Refusal is silent on
    /// the wire — a legitimate peer simply reconnects with its usual back-off.
    /// </para>
    /// </summary>
    /// <param name="transport">The new transport.</param>
    /// <param name="sourceKey">
    /// The peer's address WITHOUT the port, when this transport type can provide one. Including the
    /// port would make every connection a distinct source and the per-source limit meaningless. Null
    /// disables the per-source limit for this connection.
    /// </param>
    /// <param name="slotReserved">
    /// True when the caller already holds a slot from <see cref="TryReserveIncomingSlot"/>. The slot
    /// is then handed over rather than taken again, and this cannot return false.
    /// </param>
    /// <param name="acceptedAtUtc">
    /// When the connection was accepted, as a real <see cref="DateTime.UtcNow"/> and NOT from the
    /// system clock, which tests can shift. Null means now, which is right for a listener that only
    /// constructs an object on accept. A listener that handshakes first must pass its accept time, so
    /// that <see cref="IncomingNegotiationTimeout"/> covers both phases instead of restarting here.
    /// </param>
    /// <returns>True if the connection was admitted.</returns>
    protected bool OnIncomingTransport( Transport transport,
                                        string? sourceKey = null,
                                        bool slotReserved = false,
                                        DateTime? acceptedAtUtc = null )
    {
        Throw.CheckNotNullArgument( transport );
        return _transportManager.IncomingTransport( transport,
                                                    _transportManager.SystemClock.UtcNow,
                                                    sourceKey,
                                                    slotReserved,
                                                    acceptedAtUtc ?? DateTime.UtcNow );
    }

    /// <summary>
    /// Takes the admission slot that <see cref="OnIncomingTransport"/> would otherwise take, before
    /// doing any per-connection work.
    /// <para>
    /// A listener that only constructs an object on accept has nothing to reserve: the slot taken by
    /// <see cref="OnIncomingTransport"/> already covers everything expensive. A listener that performs
    /// a handshake first must reserve here instead, or the cap would bound only the phase that comes
    /// afterwards while the expensive one fans out unbounded — which is the shape of the problem the
    /// cap exists to prevent, moved one step earlier.
    /// </para>
    /// <para>
    /// A caller that gets true MUST either hand the slot to <see cref="OnIncomingTransport"/> with
    /// <c>slotReserved: true</c>, or give it back with <see cref="ReleaseIncomingSlot"/> — on every
    /// path, including the ones that threw.
    /// </para>
    /// </summary>
    /// <param name="sourceKey">The peer's address without the port, or null. See <see cref="OnIncomingTransport"/>.</param>
    /// <returns>True if a slot was taken.</returns>
    protected bool TryReserveIncomingSlot( string? sourceKey )
        => _transportManager.NegotiationGate.TryReserve( sourceKey );

    /// <summary>
    /// Gives back a slot taken by <see cref="TryReserveIncomingSlot"/> for a connection that never
    /// reached <see cref="OnIncomingTransport"/>.
    /// </summary>
    /// <param name="sourceKey">The same value passed to <see cref="TryReserveIncomingSlot"/>.</param>
    protected void ReleaseIncomingSlot( string? sourceKey )
        => _transportManager.NegotiationGate.Release( sourceKey );

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
        return IsListeningTypedAddress( address.TypedAddress );
    }

    /// <summary>
    /// Implements <see cref="IsListeningAddress(TransportTypeAddress)"/> on the typed address.
    /// </summary>
    /// <param name="typedAddress">The typed address to test.</param>
    /// <returns>True if this listener listens to this address, false otherwise.</returns>
    internal protected abstract bool IsListeningTypedAddress( object typedAddress );

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
