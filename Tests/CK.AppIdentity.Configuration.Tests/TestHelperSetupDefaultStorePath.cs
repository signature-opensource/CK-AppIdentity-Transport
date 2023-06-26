using CK.Core;
using NUnit.Framework;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Configuration.Tests
{
    [SetUpFixture]
    public class TestHelperSetupDefaultStorePath
    {
        [OneTimeSetUp]
        public void RunBeforeAnyTests()
        {
            var testDefault = TestHelper.TestProjectFolder.AppendPart( "TestStore" );
            ApplicationIdentityServiceConfiguration.DefaultStoreRootPath = testDefault;
            Throw.CheckState( ApplicationIdentityServiceConfiguration.DefaultStoreRootPath == testDefault );
        }
    }
}
