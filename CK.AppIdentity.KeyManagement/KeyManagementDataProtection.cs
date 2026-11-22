using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Registers the DataProtection that protects the identity keys at rest: the hosts don't call
/// <c>DataProtectionServiceCollectionExtensions.AddDataProtection()</c>.
/// <para>
/// Its application name (the discriminator of the key ring) is the full name of the application identity
/// (<c>Domain/$Party/#Environment</c>) rather than the default content root path: the keys follow the identity,
/// not the folder of the application (a moved or redeployed application still opens its keys).
/// </para>
/// <para>
/// The key ring lives in the private store of the root party and is protected by a secret key of its configuration,
/// the CNG key store (the TPM), DPAPI on Windows, or nothing (see <see cref="KeyRingStore"/>).
/// </para>
/// <para>
/// A host that sets its own application name (<c>DataProtectionBuilderExtensions.SetApplicationName</c>) keeps it, so
/// does a host that persists the key ring (<c>DataProtectionBuilderExtensions.PersistKeysToFileSystem</c>, etc.) or
/// protects it (<c>DataProtectionBuilderExtensions.ProtectKeysWithCertificate</c>, etc.).
/// </para>
/// </summary>
public sealed class KeyManagementDataProtection : IRealObject
{
    void ConfigureServices( StObjContextRoot.ServiceRegister services )
    {
        services.Services.AddDataProtection();
        // The default application name is read from the IApplicationDiscriminator (the content root by default):
        // replacing it, rather than setting the option, lets an explicit DataProtectionBuilderExtensions.SetApplicationName win.
        services.Services.AddSingleton<IApplicationDiscriminator, IdentityDiscriminator>();
        KeyRingStore.Register( services.Services );
    }

    sealed class IdentityDiscriminator : IApplicationDiscriminator
    {
        readonly ApplicationIdentityServiceConfiguration _configuration;

        public IdentityDiscriminator( ApplicationIdentityServiceConfiguration configuration ) => _configuration = configuration;

        public string? Discriminator => _configuration.FullName.Path;
    }
}
