using CK.Core;
using NUnit.Framework;

namespace CK.AppIdentity.BlobChannel.Tests;

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
