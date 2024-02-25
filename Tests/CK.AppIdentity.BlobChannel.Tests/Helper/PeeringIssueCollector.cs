using CK.AppIdentity.TransportLayer;
using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity.BlobChannel.Tests
{
    /// <summary>
    /// Simple collector of PeeringIssues events: PeeringsIssues are cloned as they arrive
    /// and stored in a list that can be retrieved when stopping the collector.
    /// </summary>
    sealed class PeeringIssueCollector
    {
        readonly TransportManagerFeature _transport;
        readonly List<PeeringIssue> _issues;
        readonly bool _skipSameKind;
        bool _stopped;

        /// <summary>
        /// Initializes a new collector. If <paramref name="skipSameKind"/> is true, consecutive
        /// same <see cref="PeeringIssue.Kind"/> are skipped.
        /// </summary>
        /// <param name="transport">The mamager feature.</param>
        /// <param name="skipSameKind">True to ignore consecutive identical <see cref="PeeringIssue.Kind"/>.</param>
        public PeeringIssueCollector( TransportManagerFeature transport, bool skipSameKind )
        {
            _transport = transport;
            _skipSameKind = skipSameKind;
            _issues = new List<PeeringIssue>();
            transport.PeeringIssueChanged.Sync += OnPeeringIssueChanged;
        }

        void OnPeeringIssueChanged( IActivityMonitor monitor, PeeringIssue e )
        {
            monitor.Info( $"(PeeringIssueCollectorTest {_transport}) PeeringIssue #{e.GetHashCode()} '{e.FullName}' {e.Kind}." );
            lock( _issues )
            {
                if( !_stopped && (!_skipSameKind || _issues.Count == 0 || _issues[^1].Kind != e.Kind) )
                {
                    _issues.Add( e.Clone() );
                }
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
                    _stopped = true;
                }
                return _issues;
            }
        }

        /// <summary>
        /// Retrieves the collected PeeringIssues do far and clears the list.
        /// </summary>
        /// <returns>The list of PeeringIssues received.</returns>
        public IReadOnlyList<PeeringIssue> GetEventsAndClear()
        {
            lock( _issues )
            {
                var a = _issues.ToArray();
                _issues.Clear();
                return a;
            }
        }
    }
}
