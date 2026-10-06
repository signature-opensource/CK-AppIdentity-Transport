using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Default <see cref="ICoreKeyStore"/>: one file per key in the owner's local store
/// (<c>-Local/CoreKeys/{name}.key</c>), holding the PKCS#8 private key protected by an
/// <see cref="IDataProtector"/> of its own purpose.
/// <para>
/// <b>Know what this protects.</b> A DataProtection purpose is a string over one key ring: whoever
/// can unprotect one purpose of this application can unprotect them all. This protects against a key
/// file that leaks without the key ring (a backup, a copied folder) and nothing more. A host that is
/// compromised gives its keys away. This is said once, at the first use, as a warning.
/// </para>
/// <para>
/// A stronger store replaces this one by taking it as a constructor parameter (and may fall back to
/// it on a host where it cannot work).
/// </para>
/// </summary>
public sealed class DefaultCoreKeyStore : ICoreKeyStore
{
    /// <summary>
    /// The folder, in each owner's local store, that holds its keys.
    /// </summary>
    public const string FolderName = "CoreKeys";

    const string Extension = ".key";
    const string ProtectorPurpose = "CK.AppIdentity.KeyManagement.DefaultCoreKeyStore";

    readonly IDataProtectionProvider _protectionProvider;
    int _warned;

    /// <summary>
    /// Initializes a new default store.
    /// </summary>
    /// <param name="protectionProvider">The data protection provider.</param>
    public DefaultCoreKeyStore( IDataProtectionProvider protectionProvider )
    {
        Throw.CheckNotNullArgument( protectionProvider );
        _protectionProvider = protectionProvider;
    }

    /// <inheritdoc />
    public ReadOnlyMemory<byte> CreateKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        var path = GetPath( owner, name );
        WarnOnce( monitor );
        Throw.CheckState( $"Key '{name}' already exists for '{owner.FullName}'.", !File.Exists( path ) );
        using var key = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        var pkcs8 = key.ExportPkcs8PrivateKey();
        try
        {
            // Zeroed only once written: a protector may hand back the very array it was given (a
            // pass-through one does), and zeroing first would then store a key of zeros.
            var protectedKey = GetProtector( owner ).Protect( pkcs8 );
            owner.LocalFileStore.CreateDirectory( path.RemoveLastPart() );
            // Atomic: a crash can never leave a truncated key behind.
            owner.LocalFileStore.WriteAllBytes( path, protectedKey );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( pkcs8 );
        }
        return key.ExportSubjectPublicKeyInfo();
    }

    /// <inheritdoc />
    public ECDsa? OpenKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        var path = GetPath( owner, name );
        if( !File.Exists( path ) ) return null;
        WarnOnce( monitor );
        byte[]? pkcs8 = null;
        try
        {
            // Never trashed on failure: this is an identity key. A protector that cannot read it today
            // (a missing or rotated key ring) is a configuration to fix, not a key to throw away.
            pkcs8 = GetProtector( owner ).Unprotect( owner.LocalFileStore.ReadAllBytes( path ) );
            var key = ECDsa.Create();
            try
            {
                key.ImportPkcs8PrivateKey( pkcs8, out int read );
                Throw.CheckData( "Trailing bytes after the private key.", read == pkcs8.Length );
                return key;
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }
        catch( Exception ex )
        {
            monitor.Error( $"Unable to open key '{name}' of '{owner.FullName}' from '{path}'. The file is left untouched.", ex );
            return null;
        }
        finally
        {
            if( pkcs8 != null ) CryptographicOperations.ZeroMemory( pkcs8 );
        }
    }

    /// <inheritdoc />
    public bool DeleteKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        var path = GetPath( owner, name );
        if( !File.Exists( path ) ) return false;
        // Deleted, not sent to the '$TrashBin': a destroyed key must not survive in a folder that
        // keeps everything else the store discards.
        owner.LocalFileStore.TryTrash( monitor, path, immediateDelete: true );
        return true;
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GetKeyNames( IActivityMonitor monitor, ILocalParty owner )
    {
        var folder = GetFolder( owner );
        if( !Directory.Exists( folder ) ) return Array.Empty<string>();
        return Directory.EnumerateFiles( folder, "*" + Extension )
                        .Select( f => Path.GetFileNameWithoutExtension( f ) )
                        .ToArray();
    }

    static NormalizedPath GetFolder( ILocalParty owner ) => owner.LocalFileStore.FolderPath.AppendPart( FolderName );

    static NormalizedPath GetPath( ILocalParty owner, string name )
    {
        Throw.CheckNotNullArgument( owner );
        Throw.CheckArgument( "A key name is 1 to 64 letters, digits, '-', '_' or '.', and does not start with '.'.",
                             !string.IsNullOrEmpty( name )
                             && name.Length <= 64
                             && name[0] != '.'
                             && name.All( c => char.IsAsciiLetterOrDigit( c ) || c == '-' || c == '_' || c == '.' ) );
        return GetFolder( owner ).AppendPart( name + Extension );
    }

    IDataProtector GetProtector( ILocalParty owner ) => _protectionProvider.CreateProtector( ProtectorPurpose, owner.FullName.Path );

    void WarnOnce( IActivityMonitor monitor )
    {
        if( Interlocked.Exchange( ref _warned, 1 ) == 0 )
        {
            monitor.Warn( $"Identity keys are kept by the {nameof( DefaultCoreKeyStore )}: files protected by DataProtection. " +
                          "This protects against a leaked key file, not against a compromised host. " +
                          $"Register a stronger {nameof( ICoreKeyStore )} where that matters." );
        }
    }
}
