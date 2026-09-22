using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.BlobChannel.Tests;

/// <summary>
/// Collector of PeeringIssue events: issues are cloned as they arrive and stored in a list that can
/// be retrieved when stopping the collector.
/// <para>
/// A <see cref="PeeringIssue"/> is a single mutable object that is raised again every time it
/// changes — the tests assert that identity — so a history has to be made of <see cref="PeeringIssue.Clone"/>
/// snapshots. That is why this keeps its own list rather than letting the
/// <see cref="PerfectEventBuffer{TEvent}"/> below be the history: the buffer stores the event as-is,
/// which here would be N references to one object all reporting its final <see cref="PeeringIssue.Kind"/>.
/// The buffer is used for what it is good at, waiting.
/// </para>
/// </summary>
sealed class PeeringIssueCollector : IDisposable
{
    readonly TransportManagerFeature _transport;
    readonly List<PeeringIssue> _issues;
    readonly PerfectEventBuffer<PeeringIssue> _signal;
    readonly bool _skipSameKind;
    PeeringIssue? _last;
    bool _stopped;

    /// <summary>
    /// Initializes a new collector. If <paramref name="skipSameKind"/> is true, consecutive
    /// same <see cref="PeeringIssue.Kind"/> are skipped.
    /// </summary>
    /// <param name="transport">The manager feature.</param>
    /// <param name="skipSameKind">True to ignore consecutive identical <see cref="PeeringIssue.Kind"/>.</param>
    public PeeringIssueCollector( TransportManagerFeature transport, bool skipSameKind )
    {
        _transport = transport;
        _skipSameKind = skipSameKind;
        _issues = new List<PeeringIssue>();
        // Order matters: Sync handlers run in subscription order, so ours must update _last BEFORE
        // the buffer pushes the event and releases a pending WaitForOneAsync. Subscribing the buffer
        // first would let a woken WaitForAsync re-read a _last that has not been updated yet and go
        // back to waiting for an event that has already happened.
        transport.PeeringIssueChanged.Sync += OnPeeringIssueChanged;
        _signal = new PerfectEventBuffer<PeeringIssue>( transport.PeeringIssueChanged );
    }

    void OnPeeringIssueChanged( IActivityMonitor monitor, PeeringIssue e )
    {
        monitor.Info( $"(PeeringIssueCollectorTest {_transport}) PeeringIssue #{e.GetHashCode()} '{e.FullName}' {e.Kind}." );
        lock( _issues )
        {
            if( !_stopped )
            {
                _last = e;
                if( !_skipSameKind || _issues.Count == 0 || _issues[^1].Kind != e.Kind )
                {
                    _issues.Add( e.Clone() );
                }
            }
        }
    }

    /// <summary>
    /// Asynchronously waits until a <paramref name="kind"/> appears, returning at once when the last
    /// received issue already has that kind.
    /// <para>
    /// This is deliberately level-triggered and does not consume: the tests await the same kind on
    /// the same collector several times in a row, and every one after the first must be a no-op. The
    /// buffer is only the wake-up signal — every <see cref="PeeringIssue.Kind"/> change raises the
    /// event, so there is nothing to observe that an event does not announce.
    /// </para>
    /// </summary>
    /// <param name="kind">The expected kind.</param>
    /// <param name="token">Cancellation token.</param>
    /// <returns>The awaitable.</returns>
    public async Task WaitForAsync( PeeringIssueKind kind, CancellationToken token )
    {
        while( _last?.Kind != kind )
        {
            await _signal.WaitForOneAsync( token );
        }
    }

    /// <summary>
    /// Stops this collector and retrieves the collected PeeringIssues.
    /// </summary>
    /// <returns>The list of PeeringIssues received.</returns>
    public IReadOnlyList<PeeringIssue> StopAndGetEvents()
    {
        lock( _issues )
        {
            if( !_stopped )
            {
                _transport.PeeringIssueChanged.Sync -= OnPeeringIssueChanged;
                _signal.Dispose();
                _stopped = true;
            }
            return _issues;
        }
    }

    /// <summary>
    /// Stops this collector if <see cref="StopAndGetEvents"/> has not been called.
    /// </summary>
    public void Dispose() => StopAndGetEvents();
}
