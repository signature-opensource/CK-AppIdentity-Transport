using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Registers the DataProtection that protects the identity keys at rest: the hosts don't call <c>AddDataProtection()</c>.
/// <para>
/// Its application name (the discriminator of the key ring) is the full name of the application identity
/// (<c>Domain/$Party/#Environment</c>) rather than the default content root path: the keys follow the identity,
/// not the folder of the application (a moved or redeployed application still opens its keys).
/// </para>
/// <para>
/// A host that sets its own application name (<c>SetApplicationName</c>) keeps it. Where the key ring is persisted
/// (<c>PersistKeysTo...</c>, <c>ProtectKeysWith...</c>) remains a deployment choice of the host.
/// </para>
/// </summary>
public sealed class KeyManagementDataProtection : IRealObject
{
    void ConfigureServices( StObjContextRoot.ServiceRegister services )
    {
        services.Services.AddDataProtection();
        services.Services.AddOptions<DataProtectionOptions>()
                         .Configure<ApplicationIdentityServiceConfiguration>( ( o, c ) => o.ApplicationDiscriminator ??= c.FullName.Path );
    }
}
