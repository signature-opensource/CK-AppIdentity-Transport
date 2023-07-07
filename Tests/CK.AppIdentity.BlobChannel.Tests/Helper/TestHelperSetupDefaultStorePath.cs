using CK.Core;
using NUnit.Framework;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests
{
    [SetUpFixture]
    public class TestHelperSetupDefaultStorePath
    {
        [OneTimeSetUp]
        public void RunBeforeAnyTests()
        {
            ApplicationIdentityServiceConfiguration.DefaultStoreRootPath = TestHelperExtension.TestStoreFolder;
            Throw.CheckState( ApplicationIdentityServiceConfiguration.DefaultStoreRootPath == TestHelperExtension.TestStoreFolder );
        }
    }
}
