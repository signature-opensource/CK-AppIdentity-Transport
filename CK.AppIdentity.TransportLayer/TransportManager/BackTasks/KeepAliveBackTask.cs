using CK.Core;
using System;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Watches one live transport for silence and asks the remote whether it is still there.
/// <para>
/// A connection can die without saying so — the peer loses power, a NAT entry expires, a cable goes.
/// Nothing notices: reads simply never complete, and writes keep succeeding into the kernel buffer
/// until it fills, so the send side is no wiser. The link stays
/// <see cref="ConnectionAvailability.Connected"/> for ever while messages queue behind it.
/// </para>
/// <para>
/// The protocol for this already existed and only the emitter was missing: the responder answers
/// <see cref="IncomingMessage.Empty"/> with <see cref="IOutgoingMessage.EmptyAck"/>
/// (<c>TransportController.Receive0Message</c>), the acknowledgment is consumed by the receive loop
/// purely so that <see cref="Transport.LastReceived"/> moves, and nothing ever sent the request.
/// </para>
/// <para>
/// Both messages are Zero Protocol, so in the run phase they are MAC'd like every other frame. That
/// is what makes this a liveness check rather than a liveness illusion: an attacker who can inject
/// bytes cannot forge an acknowledgment to hold a dead link open.
/// </para>
/// </summary>
sealed class KeepAliveBackTask : BackTask<TransportManager>
{
    Transport? _transport;
    // When the outstanding probe sequence started. Util.UtcMinValue when not probing.
    DateTime _lastProbeTime;
    int _probesSent;
    bool _reportedUnhealthy;

    public void OnInitialize( Transport transport )
    {
        Throw.DebugAssert( transport.Controller != null );
        _transport = transport;
        _lastProbeTime = Util.UtcMinValue;
        _probesSent = 0;
        _reportedUnhealthy = false;
        NextCheckDelay = 1;
    }

    public override void OnDestroy( IActivityMonitor monitor )
    {
    }

    public override void Reset()
    {
        _transport = null;
    }

    public override void Check( IActivityMonitor monitor, int previousCheckDelay )
    {
        var t = _transport;
        Throw.DebugAssert( t != null );
        var controller = t.Controller;
        // The transport is gone or dying: stop watching it. Not setting NextCheckDelay returns this
        // task to its pool, and the next connection gets a new one.
        if( controller == null || t.IsCondemned ) return;

        var settings = TaskManager.Host.Feature;
        var idle = settings.KeepAliveIdleTime;
        // Disabled. Checked every time rather than at initialization so that switching it off stops
        // existing connections probing too.
        if( idle <= TimeSpan.Zero )
        {
            if( _probesSent != 0 ) ClearProbes();
            NextCheckDelay = 1;
            return;
        }

        var now = TaskManager.Host.SystemClock.UtcNow;
        if( _probesSent == 0 )
        {
            if( now - t.LastReceived >= idle ) SendProbe( monitor, t, controller, now );
        }
        else if( t.LastReceived > _lastProbeTime )
        {
            // Anything at all came back — the acknowledgment, or ordinary traffic that answers the
            // question just as well. The sequence is over.
            monitor.Debug( $"Keep-alive answered by '{t.RemoteEndPointDescription}' after {_probesSent} probe(s)." );
            ClearProbes();
            if( _reportedUnhealthy )
            {
                _reportedUnhealthy = false;
                TaskManager.Host.SignalKeepAliveHealth( controller.Feature, healthy: true );
            }
        }
        else if( now - _lastProbeTime >= settings.KeepAliveProbeInterval )
        {
            if( _probesSent >= settings.KeepAliveProbeCount )
            {
                monitor.Warn( $"No answer from '{t.RemoteEndPointDescription}' after {_probesSent} keep-alive probes " +
                              $"({(int)(now - t.LastReceived).TotalMilliseconds} ms of silence). Killing the transport." );
                // Delay 0: the remote's own reconnection back-off decides how soon we come back, so a
                // peer that keeps going quiet is throttled by the same mechanism as one that keeps
                // dropping us. Without that this would be a new source of the tight reconnect loop.
                TaskManager.Host.KillTransport( t, 0 );
                return;
            }
            // The first unanswered interval is what an application wants to hear about: the link is
            // not gone yet, but it is no longer answering.
            if( !_reportedUnhealthy )
            {
                _reportedUnhealthy = true;
                TaskManager.Host.SignalKeepAliveHealth( controller.Feature, healthy: false );
            }
            SendProbe( monitor, t, controller, now );
        }
        NextCheckDelay = 1;
    }

    void ClearProbes()
    {
        _probesSent = 0;
        _lastProbeTime = Util.UtcMinValue;
    }

    void SendProbe( IActivityMonitor monitor, Transport t, TransportController controller, DateTime now )
    {
        // High priority: that channel is unbounded, so the probe cannot be refused nor made to wait
        // behind a backlog — which is exactly the state a sick link is in.
        if( controller.TryEnqueueHighPriority( IOutgoingMessage.Empty ) )
        {
            ++_probesSent;
            _lastProbeTime = now;
            monitor.Debug( $"Sent keep-alive probe #{_probesSent} to '{t.RemoteEndPointDescription}'." );
        }
        else
        {
            // Only happens when the channel is closed, i.e. the controller is dead: the transport is
            // on its way out and there is nothing to watch.
            monitor.Debug( $"Cannot send keep-alive probe to '{t.RemoteEndPointDescription}': the channel is closed." );
        }
    }
}
