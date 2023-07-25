using CK.AppIdentity.TransportLayer;
using CK.Core;
using FluentAssertions;
using NUnit.Framework;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests
{
    [TestFixture]
    public class PeeringIssuesTests
    {

        sealed class PeeringIssueWaiter
        {
            readonly TransportManagerFeature _transport;
            TaskCompletionSource<PeeringIssue> _nextEvent;
            PeeringIssue? _lastEvent;

            public PeeringIssueWaiter( TransportManagerFeature transport )
            {
                _transport = transport;
                _nextEvent = new TaskCompletionSource<PeeringIssue>();
                transport.PeeringIssueChanged.Sync += OnPeeringIssueChanged;
            }

            void OnPeeringIssueChanged( IActivityMonitor monitor, PeeringIssue e )
            {
                var n = _nextEvent;
                _nextEvent = new TaskCompletionSource<PeeringIssue>();
                n.SetResult( _lastEvent = e );
            }

            public PeeringIssue? LastEvent => _lastEvent;

            public Task<PeeringIssue> NextEvent => _nextEvent.Task;
        }

        [Test]
        [Timeout( 4000  )]
        public async Task Unknown_InitiatorConflict_and_Untrusted_PeeringIssueKind()
        {
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "Test/$Listener";
                c["AllowFeatures"] = "BlobChannel";
                c["AlwaysListening"] = "true";
            } );
            await listener.InitializationTask;

            var listenerTransport = listener.GetRequiredFeature<TransportManagerFeature>();
            listenerTransport.GetPeeringIssues().Should().BeEmpty();
            listenerTransport.GetClonedPeeringIssues().Should().BeEmpty();
            var peeringEvents = new PeeringIssueWaiter( listenerTransport );
            var nextEvent = peeringEvents.NextEvent;

            // Starts the sender: it is unknown for the listener. One UnknwonIncoming issue appears.
            await using var sender = await BlobChannelTester.CreateAndStartSenderAsync();
            await sender.InitializationTask;

            var theIssue = await nextEvent;
            Debug.Assert( theIssue != null );

            listenerTransport.GetPeeringIssues().Should().Contain( theIssue );
            var clonedIssues = listenerTransport.GetClonedPeeringIssues();
            clonedIssues.Should().HaveCount( 1 );
            clonedIssues[0].Should().Match<PeeringIssue>( i => i.IsClone )
                                    .And.NotBeSameAs( theIssue )
                                    .And.BeEquivalentTo( theIssue, o => o.Excluding( i => i.IsClone ) );

            theIssue.IsListener.Should().BeTrue();
            theIssue.IsInitiator.Should().BeFalse();
            theIssue.Remote.Should().BeNull();
            theIssue.Kind.Should().Be( PeeringIssueKind.UnknwonIncoming );
            Debug.Assert( theIssue.IncomingRequest != null );
            theIssue.IncomingRequest.CurrentRemoteIdentity.Should().NotBeNull();
            theIssue.IncomingRequest.FullName.Should().Be( "Test/$Sender/#Development" );
            theIssue.IncomingRequest.AvailableProtocols.Should().BeEquivalentTo( new[] { "Blob.0" } );
            theIssue.IncomingRequest.ValidClockOffset.Should().BeTrue();

            theIssue = null;
            nextEvent = peeringEvents.NextEvent;
            // Declares the sender on the listener side but with an Address. The issue kind on the listener side is InitiatorConflict.
            // (On the initiator side, since the IP is invalid, no peering issue appear, the sender simply fails to connect.)
            IRemoteParty? declaredRemote = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "$Sender";
                c["Address"] = "1.0.2.3";
            } );
            theIssue = await nextEvent;
            Debug.Assert( theIssue != null );

            theIssue.Kind.Should().Be( PeeringIssueKind.InitiatorConflict );
        }
    }
}
