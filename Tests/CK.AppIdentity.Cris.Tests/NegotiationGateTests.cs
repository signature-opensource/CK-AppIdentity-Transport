using CK.AppIdentity.TransportLayer;
using CK.Testing.AppIdentity.Cris;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

[TestFixture]
[NonParallelizable]
public class NegotiationGateTests
{
    // Their own names and port: the default ones of RunningApplication are used by the other tests.
    const int Port = 37190;

    [Test]
    public async Task an_ended_negotiation_gives_its_slot_back_without_heartbeat_Async()
    {
        // The listener has no heartbeat (the default of RunningApplication): its back tasks are never checked. Each attempt
        // of the sender is rejected (none trusts the other): the slot of an attempt must be given back when it ends, not
        // when a heartbeat checks it (never here). Before the fix, the third attempt was refused (per source cap of 2).
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: false, c =>
        {
            c["FullName"] = "Test/$GateListener";
            c["Defaults:ListeningAddress:0"] = $"tcp:127.0.0.1:{Port}";
            c["Parties:0:PartyName"] = "$GateSender";
            c["Parties:0:AutoTrustKey"] = "Never";
        }, null );
        listener.Transport.MaxConcurrentNegotiationPerSource = 2;
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, isSender: true, c =>
        {
            c["FullName"] = "Test/$GateSender";
            c["Parties:0:PartyName"] = "$GateListener";
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{Port}";
            c["Parties:0:AutoTrustKey"] = "Never";
        },
        // The initiator retries its connection on its heartbeat.
        RunningApplication.WithHeartBeat() );

        // Each rejected attempt updates the issue of the listener.
        var attempts = new HashSet<DateTime>();
        for( int i = 0; i < 300 && attempts.Count < 6 && listener.Transport.RefusedNegotiationCount == 0; ++i )
        {
            var issue = listener.Transport.GetPeeringIssues().FirstOrDefault( i => i.FullName == "Test/$GateSender/#Dev" );
            if( issue != null ) attempts.Add( issue.LastUpdated );
            await Task.Delay( 100 );
        }
        listener.Transport.RefusedNegotiationCount.ShouldBe( 0, $"The slots of the ended attempts were given back (refused after {attempts.Count} attempts)." );
        attempts.Count.ShouldBeGreaterThanOrEqualTo( 6, "The sender retries, each attempt is rejected." );
    }
}
