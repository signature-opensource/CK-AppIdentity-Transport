using CK.AppIdentity.TransportLayer;
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
        [Test]
        public async Task Unknown_InitiatorConflict_and_Untrusted_PeeringIssueKind()
        {
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "Test/$Listener";
                c["AllowFeatures"] = "BlobChannel";
            } );
            await listener.InitializationTask;

            var peeringEvents = new List<PeeringIssue>();
            var listenerTransport = listener.GetRequiredFeature<TransportManagerFeature>();
            listenerTransport.PeeringIssueChanged.Sync += ( monitor, issue ) => peeringEvents.Add( issue );
            listenerTransport.GetPeeringIssues().Should().BeEmpty();
            listenerTransport.GetClonedPeeringIssues().Should().BeEmpty();

            // Starts the sender: it is unknown for the listener. One UnknwonIncoming issue appears.
            await using var sender = await BlobChannelTester.CreateAndStartSenderAsync();
            await sender.InitializationTask;

            peeringEvents.Should().HaveCount( 1 );
            var theIssue = peeringEvents[0];
            listenerTransport.GetPeeringIssues().Should().Contain( theIssue );
            var clonedIssues = listenerTransport.GetClonedPeeringIssues();
            clonedIssues.Should().HaveCount( 1 );
            clonedIssues[0].Should().Match<PeeringIssue>( i => i.IsClone )
                                    .And.NotBeSameAs( theIssue )
                                    .And.BeEquivalentTo( theIssue );

            theIssue.IsListener.Should().BeTrue();
            theIssue.IsInitiator.Should().BeFalse();
            theIssue.Remote.Should().BeNull();
            theIssue.Kind.Should().Be( PeeringIssueKind.UnknwonIncoming );
            Debug.Assert( theIssue.IncomingRequest != null );
            theIssue.IncomingRequest.CurrentRemoteIdentity.Should().NotBeNull();
            theIssue.IncomingRequest.FullName.Should().Be( "Test/$Sender/#Development" );
            theIssue.IncomingRequest.AvailableProtocols.Should().BeEquivalentTo( new[] { "Blob.0" } );
            theIssue.IncomingRequest.ValidClockOffset.Should().BeTrue();

            peeringEvents.Clear();

            //// Declares the sender on the listener side but with an Address. The issue kind on the listener side is InitiatorConflict.
            //// (On the initiator side, since the IP is invalid, no peering issue appear, the sender simply fails to connect.)
            //IRemoteParty? declaredRemote = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
            //{
            //    c["PartyName"] = "$Sender";
            //    c["Address"] = "1.0.2.3";
            //} );

            //theIssue.Kind.Should().Be( PeeringIssueKind.InitiatorConflict );
        }
    }
}
