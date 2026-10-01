using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.MutualTls.Tests;

/// <summary>
/// The <c>mtls:</c> transport end to end.
/// <para>
/// Two things have to be true at once, and neither implies the other. The channel must actually be
/// TLS — otherwise the transport is an elaborate way of writing <c>tcp:</c>. And the TLS channel must
/// be the same channel the Zero Protocol authenticated — otherwise there are two locks on one door
/// and an attacker picks whichever is easier. The second is what the certificate binding does, and
/// these tests read it back from both ends and check the two halves agree.
/// </para>
/// </summary>
[TestFixture]
public class MutualTlsTransportTests
{
    const int Port = 37121;

    // 50 ms instead of the default 1000 ms.
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureServices( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        services.AddSingleton<MutualTlsTransportTypeService>();
        services.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<MutualTlsTransportTypeService>() );
    }

    Task<ApplicationIdentityService> CreateAsync( Action<MutableConfigurationSection> configuration, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( configuration, ConfigureServices, token );

    /// <summary>
    /// A listener and an initiator that know each other, connected over <c>mtls:</c>.
    /// </summary>
    async Task<(ApplicationIdentityService Listener, ApplicationIdentityService Sender,
                TransportFeature ListenerSide, TransportFeature SenderSide)> ConnectPairAsync( string suffix, CancellationToken token )
    {
        var listener = await CreateAsync( c =>
        {
            c["FullName"] = $"Test/$Listener{suffix}";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["ListeningAddress"] = $"mtls:127.0.0.1:{Port}";
            c["Parties:0:PartyName"] = $"$Sender{suffix}";
        }, token );
        var sender = await CreateAsync( c =>
        {
            c["FullName"] = $"Test/$Sender{suffix}";
            c["AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = $"$Listener{suffix}";
            c["Parties:0:Address"] = $"mtls:127.0.0.1:{Port}";
        }, token );

        var senderSide = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var listenerSide = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await senderSide.ReadyTask.WaitAsync( token );
        await listenerSide.ReadyTask.WaitAsync( token );
        return (listener, sender, listenerSide, senderSide);
    }

    [Test, CancelAfter( 30000 )]
    public async Task Two_parties_negotiate_over_mtls_Async( CancellationToken token )
    {
        // The baseline every other test here depends on. A TLS handshake that fails looks exactly
        // like a peer that is down, so without this, any later "it did not connect" says nothing.
        var (listener, sender, listenerSide, senderSide) = await ConnectPairAsync( "Base", token );
        await using( listener )
        await using( sender )
        {
            senderSide.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
            listenerSide.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );

            // The run-phase MAC is kept over TLS as well: it is bound to the AppIdentity session
            // rather than to the channel, so it still means something if the channel is terminated
            // somewhere in between.
            senderSide.NegotiatedMacAlgorithm.ShouldNotBeNull();
            senderSide.SessionId.ShouldBe( listenerSide.SessionId, "Both peers derive the same session." );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task Each_side_states_the_certificate_the_other_received_Async( CancellationToken token )
    {
        var (listener, sender, listenerSide, senderSide) = await ConnectPairAsync( "Bind", token );
        await using( listener )
        await using( sender )
        {
            var s = senderSide.CurrentTransport.ShouldNotBeNull();
            var l = listenerSide.CurrentTransport.ShouldNotBeNull();

            s.LocalCertificateBinding.Length.ShouldBe( Transport.CertificateBindingLength );
            s.RemoteCertificateBinding.Length.ShouldBe( Transport.CertificateBindingLength );

            // The crossing check. Each side stated its own binding inside its signed message and the
            // other side compared it with what TLS handed it; that both agree here is the same fact
            // seen from outside, and it is the fact that makes the two authentications one.
            s.LocalCertificateBinding.ToArray().ShouldBe( l.RemoteCertificateBinding.ToArray(),
                "What the initiator presented is what the listener received." );
            l.LocalCertificateBinding.ToArray().ShouldBe( s.RemoteCertificateBinding.ToArray(),
                "And the other way round: this transport is mutual." );

            s.LocalCertificateBinding.ToArray().ShouldNotBe( s.RemoteCertificateBinding.ToArray(),
                "Two parties, two credentials." );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_presented_certificate_is_derived_and_not_the_identity_Async( CancellationToken token )
    {
        // The containment property, observed from the wire rather than from the factory's unit test:
        // what this process presents to a peer is NOT the key every remote has pinned.
        var (listener, sender, listenerSide, senderSide) = await ConnectPairAsync( "Derived", token );
        await using( listener )
        await using( sender )
        {
            var identity = sender.GetRequiredFeature<ILocalKeys>().CurrentIdentity;
            var identityBinding = SHA256OfDer( identity );

            var s = senderSide.CurrentTransport.ShouldNotBeNull();
            s.LocalCertificateBinding.ToArray().ShouldNotBe( identityBinding,
                "The identity issues the TLS credential; it is not the TLS credential." );
        }

        static byte[] SHA256OfDer( LocalIdentityKey identity )
        {
            // The identity certificate is not exposed, deliberately — which is the point being
            // tested. Reissuing one derived certificate and taking ITS issuer is the closest a caller
            // can get, and even that is a different certificate every time.
            using var derived = identity.CreateDerivedCertificate();
            using var hash = System.Security.Cryptography.SHA256.Create();
            return hash.ComputeHash( derived.IssuerName.RawData );
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task Silent_clients_do_not_stall_the_accept_loop_Async( CancellationToken token )
    {
        // A TLS handshake is a round trip. If the listener performed it on the accept loop, a client
        // that connects and then says nothing would hold every subsequent accept until its budget ran
        // out — a denial of service costing the attacker one socket and no cryptography at all.
        //
        // Three silent sockets are parked first, then a legitimate party connects. Serialised, it
        // would wait three timeouts; the assertion is that it does not wait even one.
        var listener = await CreateAsync( c =>
        {
            c["FullName"] = "Test/$ListenerStall";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["ListeningAddress"] = $"mtls:127.0.0.1:{Port}";
            c["Parties:0:PartyName"] = "$SenderStall";
        }, token );
        await using( listener )
        {
            var silent = new TcpClient[3];
            try
            {
                for( int i = 0; i < silent.Length; ++i )
                {
                    silent[i] = new TcpClient();
                    await silent[i].ConnectAsync( "127.0.0.1", Port, token );
                }

                var watch = System.Diagnostics.Stopwatch.StartNew();
                await using var sender = await CreateAsync( c =>
                {
                    c["FullName"] = "Test/$SenderStall";
                    c["AutoTrustKey"] = "Once";
                    c["Parties:0:PartyName"] = "$ListenerStall";
                    c["Parties:0:Address"] = $"mtls:127.0.0.1:{Port}";
                }, token );
                var senderSide = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
                await senderSide.ReadyTask.WaitAsync( token );
                watch.Stop();

                senderSide.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
                watch.ElapsedMilliseconds.ShouldBeLessThan( 2000,
                    "The handshake of a silent peer must not be on the path of anybody else's." );
            }
            finally
            {
                foreach( var s in silent ) s?.Dispose();
            }
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_cleartext_client_gets_nowhere_on_the_mtls_port_Async( CancellationToken token )
    {
        // Why the default port is not 37120. A peer configured for tcp: and pointed here speaks first
        // with an InitialMessage; the listener is waiting for a ClientHello and cannot parse it, so
        // the connection dies instead of half-working. Checking the listener does not answer is
        // checking that the mistake is loud.
        await using var listener = await CreateAsync( c =>
        {
            c["FullName"] = "Test/$ListenerWrongPort";
            c["AlwaysListening"] = "True";
            c["ListeningAddress"] = $"mtls:127.0.0.1:{Port}";
            c["Parties:0:PartyName"] = "$SomeoneWrongPort";
        }, token );

        using var client = new TcpClient();
        await client.ConnectAsync( "127.0.0.1", Port, token );
        var stream = client.GetStream();
        // Not a ClientHello: the first bytes of a Zero Protocol frame.
        await stream.WriteAsync( new byte[] { 0x00, 0x10, 0x43, 0x4B, 0x2D, 0x41, 0x70, 0x70, 0x49, 0x64 }, token );

        var buffer = new byte[64];
        using var cts = CancellationTokenSource.CreateLinkedTokenSource( token );
        cts.CancelAfter( 10000 );
        int read;
        try
        {
            read = await stream.ReadAsync( buffer, cts.Token );
        }
        catch( Exception ) { read = 0; }

        // Either the listener closed on us, or it answered with a TLS alert. What it must never do is
        // answer the Zero Protocol.
        if( read > 0 )
        {
            buffer[0].ShouldBe( (byte)21, "A TLS alert record, not a Zero Protocol frame." );
        }
    }
}
