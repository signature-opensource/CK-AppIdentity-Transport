using CK.Core;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// A second channel ("Alpha" protocol) that only counts what it receives: with the <see cref="CountingChannelFeatureDriver"/>
/// registered before it, the channels are not registered in the order of their protocol names.
/// Opt-in: "AllowFeatures" of the remote must contain "AlphaChannel".
/// </summary>
public sealed class AlphaChannelFeatureDriver : ChannelFeatureDriver<AlphaChannelFeature>
{
    public AlphaChannelFeatureDriver( TransportFeatureDriver transport )
        : base( transport, isAllowedByDefault: false )
    {
    }

    protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out AlphaChannelFeature? channel )
    {
        channel = new AlphaChannelFeature( transport );
        return true;
    }
}

/// <summary>
/// See <see cref="AlphaChannelFeatureDriver"/>.
/// </summary>
public sealed class AlphaChannelFeature : ChannelFeature
{
    int _receivedCount;

    internal AlphaChannelFeature( TransportFeature transport )
        : base( transport )
    {
    }

    /// <summary>
    /// Gets how many messages have been received.
    /// </summary>
    public int ReceivedCount => _receivedCount;

    /// <summary>
    /// Enqueues a one byte message.
    /// </summary>
    /// <returns>True if the message has been enqueued.</returns>
    public bool TrySend()
    {
        if( CurrentHandler is not Handler h ) return false;
        var m = h.Create();
        if( h.TryEnqueue( m ) ) return true;
        m.Release();
        return false;
    }

    protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
    {
        return new Handler( this, ref c );
    }

    sealed class Handler : PeerProtocolHandler
    {
        readonly AlphaChannelFeature _feature;

        public Handler( AlphaChannelFeature feature, ref CreateParameters c )
            : base( ref c )
        {
            _feature = feature;
        }

        public IOutgoingMessage Create() => MessageFactory.Create( b => { b.GetSpan( 1 )[0] = 42; b.Advance( 1 ); } );

        protected override ValueTask ReceiveAsync( IActivityMonitor monitor, IncomingMessage message )
        {
            message.Dispose();
            Interlocked.Increment( ref _feature._receivedCount );
            return default;
        }
    }
}
