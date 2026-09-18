using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Admission control for incoming connections that have not authenticated yet.
/// <para>
/// Everything an incoming connection costs before the listener knows whether it is talking to a
/// party it has ever heard of — a pooled read buffer, a <c>Task.Run</c>, a back task, an SPKI import
/// and an ECDSA verification — is spent on an unauthenticated peer's say-so. <c>NegotiationTimeout</c>
/// bounds how long one of those lasts; it does not bound how many run at once.
/// </para>
/// <para>
/// This is a cap on <em>concurrency</em>, not a rate limit, and that is deliberate. A rate limiter
/// needs a time window and a table of who did what when, which is itself state an attacker grows and
/// which needs eviction that then needs its own bound. Counting what is in flight needs none of it:
/// an entry exists only while a negotiation is running, so <see cref="MaxTotal"/> bounds the table
/// as well as the work. What a concurrency cap does not stop is a peer completing and reconnecting
/// as fast as it can; at that point the cost is one ECDSA verification per TCP handshake, and a peer
/// able to sustain that is a network-level flood for a firewall to answer, not this layer.
/// </para>
/// <para>
/// Refusal is silent on the wire: the listener closes the connection without reading. A legitimate
/// peer reconnects with its usual back-off.
/// </para>
/// </summary>
sealed class NegotiationGate
{
    /// <summary>Default <see cref="MaxTotal"/>.</summary>
    public const int DefaultMaxTotal = 64;

    /// <summary>Default <see cref="MaxPerSource"/>.</summary>
    public const int DefaultMaxPerSource = 16;

    readonly object _lock;
    // Keyed by source address without the port. Bounded by MaxTotal: an entry is added when a
    // negotiation starts and removed when its count falls back to zero, so there is nothing to evict.
    readonly Dictionary<string, int> _perSource;
    readonly IParallelLogger _logger;
    int _count;
    int _maxTotal;
    int _maxPerSource;
    long _totalRefused;
    // Refusals come in storms. One line when a storm starts and one when it ends beats one per
    // refused connection, which would make the flood a log flood too.
    int _refusedInCurrentStorm;

    public NegotiationGate( IParallelLogger logger )
    {
        _lock = new object();
        _perSource = new Dictionary<string, int>();
        _logger = logger;
        _maxTotal = DefaultMaxTotal;
        _maxPerSource = DefaultMaxPerSource;
    }

    /// <summary>
    /// Gets or sets the maximum number of incoming negotiations that may run at once.
    /// Must be between 1 and 10000.
    /// </summary>
    public int MaxTotal
    {
        get => _maxTotal;
        set
        {
            Throw.CheckOutOfRangeArgument( value >= 1 && value <= 10000 );
            _maxTotal = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of concurrent incoming negotiations from one source address.
    /// Must be between 1 and 10000.
    /// <para>
    /// This is what stops one peer from occupying every slot of <see cref="MaxTotal"/>. Raise it when
    /// many legitimate parties share one address — several local parties on one host, or a NAT
    /// gateway in front of a fleet — since they are indistinguishable here by design.
    /// </para>
    /// </summary>
    public int MaxPerSource
    {
        get => _maxPerSource;
        set
        {
            Throw.CheckOutOfRangeArgument( value >= 1 && value <= 10000 );
            _maxPerSource = value;
        }
    }

    /// <summary>
    /// Gets the number of incoming negotiations currently in flight.
    /// </summary>
    public int Count
    {
        get { lock( _lock ) return _count; }
    }

    /// <summary>
    /// Gets how many incoming connections have been refused since the start.
    /// </summary>
    public long TotalRefused
    {
        get { lock( _lock ) return _totalRefused; }
    }

    /// <summary>
    /// Attempts to take a slot for a new incoming negotiation.
    /// <para>
    /// A caller that gets true MUST eventually <see cref="Release(string?)"/> with the same
    /// <paramref name="sourceKey"/>.
    /// </para>
    /// </summary>
    /// <param name="sourceKey">
    /// The peer's address without the port, or null when the transport type cannot provide one — the
    /// per-source limit is then not applied and only <see cref="MaxTotal"/> holds.
    /// </param>
    /// <returns>True if a slot was taken.</returns>
    public bool TryReserve( string? sourceKey )
    {
        lock( _lock )
        {
            int fromSource = 0;
            if( sourceKey != null ) _perSource.TryGetValue( sourceKey, out fromSource );
            if( _count >= _maxTotal || (sourceKey != null && fromSource >= _maxPerSource) )
            {
                ++_totalRefused;
                if( _refusedInCurrentStorm++ == 0 )
                {
                    _logger.Warn( $"Refusing incoming connection from '{sourceKey ?? "<unknown source>"}': " +
                                  $"{_count} negotiations in flight (max {_maxTotal}), {fromSource} from this source " +
                                  $"(max {_maxPerSource}). Further refusals are counted, not logged." );
                }
                return false;
            }
            if( _refusedInCurrentStorm > 0 )
            {
                _logger.Info( $"Accepting incoming connections again after refusing {_refusedInCurrentStorm}." );
                _refusedInCurrentStorm = 0;
            }
            ++_count;
            if( sourceKey != null ) _perSource[sourceKey] = fromSource + 1;
            return true;
        }
    }

    /// <summary>
    /// Gives back a slot taken by <see cref="TryReserve(string?)"/>.
    /// </summary>
    /// <param name="sourceKey">The same value passed to <see cref="TryReserve(string?)"/>.</param>
    public void Release( string? sourceKey )
    {
        lock( _lock )
        {
            Throw.DebugAssert( "Release is called once per successful TryReserve.", _count > 0 );
            if( _count > 0 ) --_count;
            if( sourceKey != null && _perSource.TryGetValue( sourceKey, out var fromSource ) )
            {
                if( fromSource <= 1 ) _perSource.Remove( sourceKey );
                else _perSource[sourceKey] = fromSource - 1;
            }
        }
    }
}
