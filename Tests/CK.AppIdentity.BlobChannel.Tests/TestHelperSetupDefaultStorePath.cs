using CK.Core;
using NUnit.Framework;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests;

/// <summary>
/// Points the store at THIS project's folder.
/// <para>
/// It is duplicated in every test assembly rather than shared, and must stay that way: NUnit
/// discovers a SetUpFixture only in the assembly under test, and a shared one would resolve
/// <c>TestProjectFolder</c> to wherever the shared library was built — two assemblies then clear and
/// rewrite one store while both are running.
/// </para>
/// </summary>
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
