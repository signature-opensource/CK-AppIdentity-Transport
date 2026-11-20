using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The pre-authorized enlistment ticket: a party that starts with a ticket of its center is trusted by the center at once
/// (no approval code, no pending approval) and verifies the center from the anchor of the ticket. While a ticket is open
/// for a party, a key presented without a valid proof is refused.
/// </summary>
[TestFixture]
public class EnlistTicketTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    // The center's side, in memory: the tickets by party full name (the real one is the Authentication Center's).
    sealed class TestTicketAuthority : IEnlistmentTicketAuthority
    {
        public readonly Dictionary<string, (string Id, byte[] PublicKey, string? UsedBy)> Tickets = new();
        public string HolderFullName = "";

        public bool HasOpenTicket( ILocalParty local, string partyFullName )
            => local.FullName.Path == HolderFullName && Tickets.TryGetValue( partyFullName, out var t ) && t.UsedBy == null;

        public bool TryUse( IParallelLogger logger, ILocalParty local, string partyFullName, ReadOnlySpan<byte> proof,
                            KeyCheckpoint identity, string keyFingerprint, ReadOnlySpan<byte> ephemeralPublicKey )
        {
            if( !HasOpenTicket( local, partyFullName ) ) return false;
            var t = Tickets[partyFullName];
            if( EnlistTicket.GetProofId( proof ) != t.Id
                || !EnlistTicket.VerifyProof( t.PublicKey, proof, partyFullName, identity, local.FullName.Path, ephemeralPublicKey ) )
            {
                return false;
            }
            Tickets[partyFullName] = (t.Id, t.PublicKey, keyFingerprint);
            return true;
        }

        public string? Open( IActivityMonitor monitor, ILocalParty local, string partyFullName, TimeSpan lifetime, int operatorActorId ) => throw new NotSupportedException();
        public KeyCheckpoint? Register( IActivityMonitor monitor, ILocalParty local, string ticketId, string partyFullName, byte[] publicKey, DateTime expires, int operatorActorId ) => throw new NotSupportedException();
        public IReadOnlyList<EnlistmentTicketInfo> GetTickets( ILocalParty local ) => [];
        public bool Revoke( IActivityMonitor monitor, ILocalParty local, string ticketId ) => false;
    }

    void Configure( ServiceCollection services, TestTicketAuthority? authority )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        if( authority != null ) services.AddSingleton<IEnlistmentTicketAuthority>( authority );
    }

    // The center (it listens) with an expected party as a remote (approved by an operator otherwise).
    async Task<ApplicationIdentityService> CreateCenterAsync( string name, TestTicketAuthority authority, CancellationToken token )
    {
        PeerStore.ClearRemoteTrust( $"Test/${name}Center" );
        PeerStore.ClearRemoteTrust( $"Test/${name}Party" );
        var center = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}Center";
            c["Defaults:Transport:AlwaysListening"] = "True";
            c["Defaults:KeyManagement:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = $"${name}Party";
        }, s => Configure( s, authority ), token: token );
        authority.HolderFullName = center.FullName.Path;
        return center;
    }

    // Opens a ticket on the center for the party: its text, given to the party.
    static string OpenTicket( ApplicationIdentityService center, TestTicketAuthority authority, string partyFullName, DateTime? expires = null )
    {
        var checkpoint = center.GetRequiredFeature<ILocalKeys>().Checkpoint;
        using var ticket = EnlistTicket.Create( center.FullName.Path, checkpoint, expires ?? DateTime.UtcNow.AddHours( 1 ), out var publicKey );
        authority.Tickets[partyFullName] = (ticket.IdText, publicKey, null);
        return ticket.Encode();
    }

    Task<ApplicationIdentityService> CreatePartyAsync( string name, string? ticket, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}Party";
            c["Defaults:KeyManagement:AutoTrustKey"] = "Never";
            if( ticket != null ) c["Local:KeyManagement:EnlistTicket"] = ticket;
            c["Parties:0:PartyName"] = $"${name}Center";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, s => Configure( s, null ), token: token );

    static async Task<bool> WaitForAsync( Func<bool> condition, int seconds, CancellationToken token )
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( DateTime.UtcNow < deadline )
        {
            if( condition() ) return true;
            await Task.Delay( 50, token );
        }
        return false;
    }

    [Test]
    public void a_ticket_is_text_and_its_proof_is_bound_to_the_party_the_holder_and_the_connection()
    {
        var checkpoint = KeyCheckpoint.TryParse( $"3:{new string( 'a', 64 )}", out var c, out _ ) ? c : null;
        checkpoint.ShouldNotBeNull();
        var expires = new DateTime( 2030, 1, 2, 3, 4, 5, DateTimeKind.Utc );
        using var ticket = EnlistTicket.Create( "Test/$Center/#Dev", checkpoint, expires, out var publicKey );
        var text = ticket.Encode();
        text.ShouldStartWith( EnlistTicket.Prefix );

        EnlistTicket.TryParse( text, out var read, out var error ).ShouldBeTrue( error );
        using( read )
        {
            read.IdText.ShouldBe( ticket.IdText );
            read.CenterFullName.ShouldBe( "Test/$Center/#Dev" );
            read.CenterCheckpoint.ShouldBe( checkpoint );
            read.Expires.ShouldBe( expires );

            var identity = KeyCheckpoint.TryParse( $"0:{new string( 'b', 64 )}", out var i, out _ ) ? i : null;
            var ephemeral = RandomNumberGenerator.GetBytes( 65 );
            var proof = read.SignProof( "Test/$Party/#Dev", identity!, "Test/$Center/#Dev", ephemeral );
            EnlistTicket.GetProofId( proof ).ShouldBe( ticket.IdText );
            EnlistTicket.VerifyProof( publicKey, proof, "Test/$Party/#Dev", identity!, "Test/$Center/#Dev", ephemeral ).ShouldBeTrue();
            // Another party, another holder, another connection: refused.
            EnlistTicket.VerifyProof( publicKey, proof, "Test/$Other/#Dev", identity!, "Test/$Center/#Dev", ephemeral ).ShouldBeFalse();
            EnlistTicket.VerifyProof( publicKey, proof, "Test/$Party/#Dev", identity!, "Test/$Other/#Dev", ephemeral ).ShouldBeFalse();
            EnlistTicket.VerifyProof( publicKey, proof, "Test/$Party/#Dev", identity!, "Test/$Center/#Dev", RandomNumberGenerator.GetBytes( 65 ) ).ShouldBeFalse();
        }
        EnlistTicket.TryParse( "ckt1.!!", out _, out _ ).ShouldBeFalse();
        EnlistTicket.TryParse( "nope", out _, out var prefixError ).ShouldBeFalse();
        prefixError.ShouldContain( EnlistTicket.Prefix );
    }

    [Test, CancelAfter( 60000 )]
    public async Task a_party_with_a_ticket_is_trusted_at_once_and_trusts_its_center_from_the_ticket_Async( CancellationToken token )
    {
        var authority = new TestTicketAuthority();
        await using var center = await CreateCenterAsync( "Tk1", authority, token );
        var ticket = OpenTicket( center, authority, "Test/$Tk1Party/#Dev" );
        await using var party = await CreatePartyAsync( "Tk1", ticket, token );

        // The party anchors its center at the checkpoint of the ticket.
        party.GetRequiredFeature<ILocalKeys>().TrustAnchors.ShouldContainKey( center.FullName.Path );

        var partyTransport = party.Remotes.Single().GetRequiredFeature<TransportFeature>();
        (await WaitForAsync( () => partyTransport.ConnectionAvailability == ConnectionAvailability.Connected, 30, token ))
            .ShouldBeTrue( "The center trusts the key of the ticket's party: no approval." );
        authority.Tickets["Test/$Tk1Party/#Dev"].UsedBy.ShouldNotBeNull( "The ticket is used: it records the key it enlisted." );
        center.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().ShouldBeEmpty( "No pending approval." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task while_a_ticket_is_open_a_key_without_its_proof_is_refused_Async( CancellationToken token )
    {
        var authority = new TestTicketAuthority();
        await using var center = await CreateCenterAsync( "Tk2", authority, token );
        OpenTicket( center, authority, "Test/$Tk2Party/#Dev" );
        // A stranger under the expected name, without the ticket (it trusts the center on first use for the test).
        await using var stranger = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Tk2Party";
            c["Defaults:KeyManagement:AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = "$Tk2Center";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, s => Configure( s, null ), token: token );

        // Its attempts are refused: no pending approval on the center, the ticket stays open.
        await Task.Delay( 3000, token );
        center.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().ShouldBeEmpty( "No pending approval for a key without the ticket." );
        authority.Tickets["Test/$Tk2Party/#Dev"].UsedBy.ShouldBeNull();
        stranger.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability.ShouldNotBe( ConnectionAvailability.Connected );
    }

    [Test, CancelAfter( 60000 )]
    public async Task a_proof_of_another_ticket_is_refused_Async( CancellationToken token )
    {
        var authority = new TestTicketAuthority();
        await using var center = await CreateCenterAsync( "Tk3", authority, token );
        // The ticket given to the party is not the one the center holds for it.
        var given = OpenTicket( center, authority, "Test/$Tk3Party/#Dev" );
        OpenTicket( center, authority, "Test/$Tk3Party/#Dev" );
        await using var party = await CreatePartyAsync( "Tk3", given, token );

        await Task.Delay( 3000, token );
        party.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability.ShouldNotBe( ConnectionAvailability.Connected );
        authority.Tickets["Test/$Tk3Party/#Dev"].UsedBy.ShouldBeNull();
        center.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().ShouldBeEmpty();
    }
}
