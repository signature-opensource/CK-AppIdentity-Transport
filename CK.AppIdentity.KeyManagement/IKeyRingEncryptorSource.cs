using CK.Core;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Implemented by an <see cref="ICoreKeyStore"/> that can also protect the DataProtection key ring (see
/// <see cref="KeyRingStore"/>): the CNG store of CK.AppIdentity.KeyManagement.Cng wraps the content keys of the ring by a
/// key of its provider (the TPM by default). Used when the root party doesn't configure "KeyManagement:KeyRingKey".
/// </summary>
public interface IKeyRingEncryptorSource
{
    /// <summary>
    /// Gets the encryptor of the key ring of the process, or null when this store doesn't protect it for
    /// <paramref name="root"/> (the next protection applies: DPAPI on Windows).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="root">The root party: the owner of the key ring.</param>
    /// <returns>The encryptor or null.</returns>
    IXmlEncryptor? GetKeyRingEncryptor( IActivityMonitor monitor, ILocalParty root );
}
