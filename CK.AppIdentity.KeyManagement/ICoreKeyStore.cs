using CK.Core;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Holds the private identity keys of the local parties.
/// <para>
/// Keys are created <b>inside</b> the store and are reachable only through a handle: an
/// implementation may make them non-exportable (a TPM, an HSM). There is deliberately no import:
/// a key that never existed outside the store cannot have leaked from anywhere else.
/// </para>
/// <para>
/// Names are scoped by their <c>owner</c> and are opaque to the store. <see cref="ILocalKeys"/> names
/// a key by its position in the party's key event log ("0", "1", ...), so nothing is ever renamed.
/// </para>
/// <para>
/// The default implementation is <see cref="DefaultCoreKeyStore"/>. Another implementation replaces
/// it by taking it as a constructor parameter, which also lets it fall back to it.
/// </para>
/// </summary>
public interface ICoreKeyStore : ISingletonAutoService
{
    /// <summary>
    /// Generates a new P-256 key pair inside the store.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="owner">The party that owns the key.</param>
    /// <param name="name">The key name. Must not exist.</param>
    /// <returns>The SubjectPublicKeyInfo of the new key.</returns>
    ReadOnlyMemory<byte> CreateKey( IActivityMonitor monitor, ILocalParty owner, string name );

    /// <summary>
    /// Opens a handle on a key. The caller owns the handle and must dispose it.
    /// <para>
    /// The private part may be non-exportable: callers sign through the handle, they never read the key.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="owner">The party that owns the key.</param>
    /// <param name="name">The key name.</param>
    /// <returns>The handle, or null if there is no such key or it cannot be opened (an error is logged then).</returns>
    ECDsa? OpenKey( IActivityMonitor monitor, ILocalParty owner, string name );

    /// <summary>
    /// Destroys a key.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="owner">The party that owns the key.</param>
    /// <param name="name">The key name.</param>
    /// <returns>True when the key existed.</returns>
    bool DeleteKey( IActivityMonitor monitor, ILocalParty owner, string name );

    /// <summary>
    /// Gets the names of the keys of an owner.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="owner">The party that owns the keys.</param>
    /// <returns>The key names.</returns>
    IReadOnlyList<string> GetKeyNames( IActivityMonitor monitor, ILocalParty owner );
}
