using CK.AppIdentity.TransportLayer.Tests.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The other two readers that must not act on a self-asserted signature:
/// <c>ReadEvictionDisallowedMessage</c> and <c>TryReadMissingProtocolsMessage</c>. Acting on a
/// signature that verifies against a key the sender supplied in the same message authenticates
/// nobody — anyone can produce one.
/// <para>
/// Neither is as damaging as the OffRemote case (they raise a diagnostic and set a retry delay
/// rather than taking the remote down), but both let an unauthenticated peer write into the
/// operator's <c>PeeringIssue</c> diagnostics — which is what the observable below checks.
/// </para>
/// </summary>
[TestFixture]
public class C2OtherReadersTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    /// <summary>
    /// Runs the shared shape: establish trust, then reply to the next negotiation with
    /// <paramref name="craft"/> signed by the given key, and return the issue kinds raised.
    /// </summary>
    async Task<IReadOnlyList<PeeringIssueKind>> RunAttackAsync( string localName,
                                                                string remoteName,
                                                                Func<PeerInitialMessage, PeerIdentity, byte[]> craft,
                                                                bool signWithTrustedKey,
                                                                CancellationToken token )
    {
        PeerStore.ClearRemoteTrust( $"Test/{remoteName}" );

        await using var peer = new AdversarialPeer();
        using var goodKey = PeerIdentity.Create();
        using var evilKey = PeerIdentity.Create();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{localName}";
            c["Parties:0:PartyName"] = remoteName;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var manager = sender.GetRequiredFeature<TransportManagerFeature>();

        // 1. Legitimate handshake pins goodKey.
        await using( var c1 = await peer.AcceptAsync( token ) )
        {
            var initial = await c1.ReadInitialMessageAsync( token );
            await c1.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, new[] { goodKey } ), token );
            (await c1.ReadFrameAsync( token )).Discriminator
                .ShouldBe( PeerMessages.DNegoFinalSuccessMessage, "The baseline handshake must succeed first." );
            await feature.ReadyTask.WaitAsync( token );
        }

        var kinds = new List<PeeringIssueKind>();
        void OnIssue( IActivityMonitor m, PeeringIssue e )
        {
            lock( kinds ) kinds.Add( e.Kind );
        }
        manager.PeeringIssueChanged.Sync += OnIssue;
        try
        {
            // 2. The reply under test, on the next negotiation.
            await using( var c2 = await peer.AcceptAsync( token ) )
            {
                var initial2 = await c2.ReadInitialMessageAsync( token );
                await c2.SendZeroFrameAsync( craft( initial2, signWithTrustedKey ? goodKey : evilKey ), token );
            }
            // Give the manager loop time to surface any issue.
            await Task.Delay( 1500, token );
        }
        finally
        {
            manager.PeeringIssueChanged.Sync -= OnIssue;
        }
        lock( kinds ) return kinds.ToArray();
    }

    [Test, CancelAfter( 40000 )]
    public async Task A_self_asserted_EvictionDisallowed_raises_no_issue_Async( CancellationToken token )
    {
        var kinds = await RunAttackAsync(
            "$C2EvictEvil", "$AdvEvictEvil",
            ( initial, key ) => PeerMessages.EvictionDisallowed( initial.Nonce, new[] { key } ),
            signWithTrustedKey: false,
            token );

        kinds.ShouldNotContain( PeeringIssueKind.RemoteDisallowEviction,
            "An EvictionDisallowed signed by an untrusted key must be ignored: otherwise any peer " +
            "answering on this connection can write into the operator's diagnostics (finding C2)." );
    }

    [Test, CancelAfter( 40000 )]
    public async Task A_trusted_EvictionDisallowed_does_raise_the_issue_Async( CancellationToken token )
    {
        // Positive control: the same message from the trusted key must be honoured, otherwise the
        // negative test above could pass simply because the harness builds an unparseable message.
        var kinds = await RunAttackAsync(
            "$C2EvictOk", "$AdvEvictOk",
            ( initial, key ) => PeerMessages.EvictionDisallowed( initial.Nonce, new[] { key } ),
            signWithTrustedKey: true,
            token );

        kinds.ShouldContain( PeeringIssueKind.RemoteDisallowEviction,
            "An EvictionDisallowed signed by the TRUSTED key must raise the issue." );
    }

    [Test, CancelAfter( 40000 )]
    public async Task A_self_asserted_MissingProtocols_raises_no_issue_Async( CancellationToken token )
    {
        var kinds = await RunAttackAsync(
            "$C2MissEvil", "$AdvMissEvil",
            ( initial, key ) => PeerMessages.MissingProtocols( initial.Nonce,
                                                               new[] { "Fake.1" },
                                                               new[] { "Other.1" },
                                                               new[] { key } ),
            signWithTrustedKey: false,
            token );

        kinds.ShouldNotContain( PeeringIssueKind.MissingProtocols,
            "A MissingProtocols signed by an untrusted key must be ignored (finding C2)." );
    }

    [Test, CancelAfter( 40000 )]
    public async Task A_trusted_MissingProtocols_does_raise_the_issue_Async( CancellationToken token )
    {
        var kinds = await RunAttackAsync(
            "$C2MissOk", "$AdvMissOk",
            ( initial, key ) => PeerMessages.MissingProtocols( initial.Nonce,
                                                               new[] { "Fake.1" },
                                                               new[] { "Other.1" },
                                                               new[] { key } ),
            signWithTrustedKey: true,
            token );

        kinds.ShouldContain( PeeringIssueKind.MissingProtocols,
            "A MissingProtocols signed by the TRUSTED key must raise the issue." );
    }
}
