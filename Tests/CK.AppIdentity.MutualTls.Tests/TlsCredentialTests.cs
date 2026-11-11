using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.MutualTls.Tests;

[TestFixture]
public class TlsCredentialTests
{
    [Test, CancelAfter( 30000 )]
    public async Task each_local_identity_keeps_its_certificate_Async( CancellationToken token )
    {
        // TR-10: a single cached certificate: alternating local identities (the application and a tenant domain)
        // issued a new certificate on every connection.
        await using var a = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = "Test/$TlsCredA", token: token );
        await using var b = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = "Test/$TlsCredB", token: token );
        var keysA = a.GetRequiredFeature<ILocalKeys>();
        var keysB = b.GetRequiredFeature<ILocalKeys>();

        var credential = new TlsCredential();
        var (certA, bindingA) = credential.Get( keysA );
        var (certB, _) = credential.Get( keysB );
        certB.ShouldNotBeSameAs( certA );

        var (certA2, bindingA2) = credential.Get( keysA );
        certA2.ShouldBeSameAs( certA, "Another identity in between doesn't issue a new certificate." );
        bindingA2.ToArray().ShouldBe( bindingA.ToArray() );
        credential.Get( keysB ).Certificate.ShouldBeSameAs( certB );

        // A rotation issues a new one.
        keysA.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        credential.Get( keysA ).Certificate.ShouldNotBeSameAs( certA );
    }
}
