using CK.Core;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// A channel that exists only to observe the send hooks of <see cref="PeerProtocolHandler"/>.
/// <para>
/// Messages carry a small int identity that is both the payload and the
/// <see cref="IOutgoingMessageData.Source"/>, so an attempt can be attributed to a message across
/// transports: the handler is recreated on every reconnection, the counters are not.
/// </para>
/// </summary>
public sealed partial class CountingChannelFeature : ChannelFeature
{
    readonly ConcurrentDictionary<int, int> _attempts;
    readonly ConcurrentDictionary<int, int> _sent;
    readonly ConcurrentQueue<int> _received;
    readonly CountingChannelFeatureDriver _driver;
    int _handlerChangedCount;

    internal CountingChannelFeature( CountingChannelFeatureDriver driver, TransportFeature transport )
        : base( transport )
    {
        _driver = driver;
        _attempts = new ConcurrentDictionary<int, int>();
        _sent = new ConcurrentDictionary<int, int>();
        _received = new ConcurrentQueue<int>();
    }

    new Protocol? CurrentHandler => Unsafe.As<Protocol?>( base.CurrentHandler );

    /// <summary>
    /// Gets how many times <see cref="PeerProtocolHandler.OnSendMessage"/> ran for a message.
    /// </summary>
    public int AttemptCount( int id ) => _attempts.TryGetValue( id, out var c ) ? c : 0;

    /// <summary>
    /// Gets how many times <see cref="PeerProtocolHandler.OnMessageSent"/> ran for a message.
    /// </summary>
    public int SentCount( int id ) => _sent.TryGetValue( id, out var c ) ? c : 0;

    /// <summary>
    /// Gets the identities received from the remote, in order.
    /// </summary>
    public IReadOnlyCollection<int> Received => _received;

    /// <summary>
    /// When set, the first <see cref="PeerProtocolHandler.OnSendMessage"/> for this identity blocks
    /// until <see cref="SendGate"/> is set. This holds the message inside the send loop, between the
    /// hook and the actual write, which is the only window where the transport can die under it.
    /// </summary>
    public int GatedId { get; set; } = -1;

    /// <summary>
    /// Gets the gate that releases <see cref="GatedId"/>.
    /// </summary>
    public ManualResetEventSlim SendGate { get; } = new ManualResetEventSlim( false );

    /// <summary>
    /// Signaled once the gated message has entered <see cref="PeerProtocolHandler.OnSendMessage"/>:
    /// the send loop is now parked and the test can act on the transport.
    /// </summary>
    public ManualResetEventSlim GateEntered { get; } = new ManualResetEventSlim( false );

    /// <summary>
    /// When true, <see cref="PeerProtocolHandler.OnMessageSent"/> throws. The send must be unaffected.
    /// </summary>
    public bool ThrowOnMessageSent { get; set; }

    /// <summary>
    /// When set, <see cref="PeerProtocolHandler.OnSendMessage"/> returns false for this identity: the
    /// message is skipped and must never reach <see cref="PeerProtocolHandler.OnMessageSent"/>.
    /// </summary>
    public int SkippedId { get; set; } = -1;

    /// <summary>
    /// When set, <see cref="PeerProtocolHandler.OnSendMessage"/> throws for this identity: the message
    /// must be dropped without killing the transport.
    /// </summary>
    public int ThrowOnSendId { get; set; } = -1;

    /// <summary>
    /// When set, <see cref="PeerProtocolHandler.ReceiveAsync"/> throws for this identity (after having
    /// disposed the message): the message must be skipped without killing the transport.
    /// </summary>
    public int ThrowOnReceiveId { get; set; } = -1;

    /// <summary>
    /// Gets how many times <see cref="OnCurrentHandlerChanged"/> ran.
    /// </summary>
    public int HandlerChangedCount => _handlerChangedCount;

    /// <summary>
    /// Gets whether <see cref="Teardown"/> ran.
    /// </summary>
    public bool TornDown { get; private set; }

    /// <summary>
    /// Enqueues a message identified by <paramref name="id"/>.
    /// </summary>
    /// <param name="id">The message identity. Must be positive.</param>
    /// <returns>True if the message has been enqueued.</returns>
    public bool TrySend( int id )
    {
        Throw.CheckArgument( id > 0 );
        var h = CurrentHandler;
        if( h == null ) return false;
        var message = h.CreateMessage( id );
        if( h.TryEnqueue( message ) ) return true;
        message.Release();
        return false;
    }

    protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
    {
        if( _driver.CreateHandlerFailures > 0 )
        {
            --_driver.CreateHandlerFailures;
            throw new CKException( "CreateHandler failure." );
        }
        return new Protocol( this, ref c );
    }

    protected override void OnCurrentHandlerChanged( IActivityMonitor monitor, PeerProtocolHandler? previous, PeerProtocolHandler? current )
    {
        Interlocked.Increment( ref _handlerChangedCount );
        if( _driver.ThrowOnHandlerChanged )
        {
            throw new CKException( "OnCurrentHandlerChanged failure." );
        }
    }

    protected override void Teardown( FeatureLifetimeContext context )
    {
        TornDown = true;
        if( _driver.ThrowOnTeardown )
        {
            throw new CKException( "Teardown failure." );
        }
    }
}
