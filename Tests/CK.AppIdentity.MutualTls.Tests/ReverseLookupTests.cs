using CK.AppIdentity.TransportLayer;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Monitoring;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.MutualTls.Tests;

/// <summary>
/// The listener working out who is connecting from the certificate, before the peer has said
/// anything.
/// <para>
/// This is the one piece of §5 that the attestation binding did not already cover, and it is defence
/// in depth rather than the binding itself: what it produces is fed to the incoming path, which holds
/// it against the signed InitialMessage. A peer that makes it resolve to somebody else has to hold
/// that somebody's identity private key, and is then caught claiming a different name in a message it
/// signed itself.
/// </para>
/// <para>
/// It only works for a party already trusted, and that is not a limitation to fix: the lookup is
/// "whose pinned identity signed this certificate?", and on first contact there is no pinned identity
/// to ask. First contact resolves to nothing and takes the same path a cleartext connection takes,
/// which is what keeps trust-on-first-use working here.
/// </para>
/// </summary>
[TestFixture]
public class ReverseLookupTests
{
    const int Port = 37122;

    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureServices( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        services.AddSingleton<MutualTlsTransportTypeService>();
        services.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<MutualTlsTransportTypeService>() );
    }

    Task<ApplicationIdentityService> CreateAsync( Action<MutableConfigurationSection> configuration, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( configuration, ConfigureServices, token );

    Task<ApplicationIdentityService> CreateListenerAsync( CancellationToken token )
        => CreateAsync( c =>
        {
            c["FullName"] = "Test/$LookupListener";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["ListeningAddress"] = $"mtls:127.0.0.1:{Port}";
            c["Parties:0:PartyName"] = "$LookupSender";
        }, token );

    Task<ApplicationIdentityService> CreateSenderAsync( CancellationToken token )
        => CreateAsync( c =>
        {
            c["FullName"] = "Test/$LookupSender";
            c["AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = "$LookupListener";
            c["Parties:0:Address"] = $"mtls:127.0.0.1:{Port}";
        }, token );

    static async Task ConnectAndWaitAsync( ApplicationIdentityService listener, ApplicationIdentityService sender, CancellationToken token )
    {
        await sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
        await listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_trusted_party_is_identified_from_its_certificate_Async( CancellationToken token )
    {
        // Two connections are needed and that is the point of the test as much as its setup. The
        // first establishes trust: with no pinned identity there is nothing to check a signature
        // against, so the listener cannot know who this is and does not pretend to. The second is
        // the one that resolves.
        PeerStore.ClearRemoteTrust( "Test/$LookupSender" );
        PeerStore.ClearRemoteTrust( "Test/$LookupListener" );

        await using var listener = await CreateListenerAsync( token );

        using var logCollector = GrandOutput.Default!.CreateMemoryCollector( 1000 );
        const string identified = "Incoming mTLS connection identified as 'Test/$LookupSender/#Dev' from its certificate.";

        await using( var first = await CreateSenderAsync( token ) )
        {
            await ConnectAndWaitAsync( listener, first, token );
        }
        logCollector.ExtractCurrentTexts().ShouldNotContain( identified,
            "Nothing was trusted yet, so there was no key to check the certificate against." );

        // Same party, new process: the trust established above is in the store, so this time the
        // listener has something to check against.
        await using( var second = await CreateSenderAsync( token ) )
        {
            await ConnectAndWaitAsync( listener, second, token );
            var texts = await PollForAsync( logCollector, identified, token );
            texts.ShouldContain( identified,
                "The certificate carries no identity key of its own - what names the party is the " +
                "signature the identity put on it." );
        }
    }

    /// <summary>
    /// The listener logs from its own loop, so the line can land slightly after the connection is
    /// ready. Accumulates, because extracting drains the collector.
    /// </summary>
    static async Task<List<string>> PollForAsync( GrandOutputMemoryCollector collector, string expected, CancellationToken token )
    {
        var all = new List<string>();
        for( int i = 0; i < 100; ++i )
        {
            all.AddRange( collector.ExtractCurrentTexts() );
            if( all.Contains( expected ) ) break;
            await Task.Delay( 50, token );
        }
        return all;
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_stranger_is_not_identified_and_still_gets_in_Async( CancellationToken token )
    {
        // The rule the lookup must not break. An unknown certificate resolves to nothing, and that
        // has to leave the connection exactly where a cleartext one would be - otherwise deciding
        // trust would have moved into the transport, and no new party could ever be adopted.
        const string remote = "$LookupStranger";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        using var cert = PeerCertificate.Create();
        await using var peer = new AdversarialPeer( cert );
        using var peerKey = PeerIdentity.Create();

        await using var sender = await CreateAsync( c =>
        {
            c["FullName"] = "Test/$LookupStrangerInit";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, token );
        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using var c = await peer.AcceptAsync( token );
        var initial = await c.ReadInitialMessageAsync( token );
        await c.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial,
                                                                    _systemClock.UtcNow,
                                                                    new[] { peerKey },
                                                                    certificateBinding: c.TruthfulBinding ), token );

        await feature.ReadyTask.WaitAsync( token );
        feature.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected,
            "A self-signed certificate nobody issued must not stop a party being adopted." );
    }
}
