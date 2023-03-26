using NUnit.Framework;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests
{
    [TestFixture]
    public class NegociationTests
    {
        [Test]
        public async Task Protocols_are_Features_Async()
        {
            await using var app1 = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "App1";
                c["Remotes:0:Name"] = "App2";
            } );
            await using var app2 = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "App2";
                c["Remotes:0:Name"] = "App1";
            } );


        }
    }
}
