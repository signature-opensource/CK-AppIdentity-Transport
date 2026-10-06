using CK.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// An <see cref="ICoreKeyStore"/> that keeps the identity keys in the TPM, through the Windows CNG
/// "Microsoft Platform Crypto Provider": the keys are created inside the chip, are not exportable, and
/// every signature is made by the chip. A host that is copied, backed up or stolen gives up no key.
/// <para>
/// What it does not prevent: an attacker running code on the host while it is compromised can USE the
/// keys (but never take them away). That is what the offline recovery key is for
/// (<see cref="ILocalKeys.Recover"/>).
/// </para>
/// <para>
/// <b>It covers the <see cref="DefaultCoreKeyStore"/></b> (it takes it as its constructor parameter, which
/// is how the automatic DI makes it replace it) and falls back to it when no TPM is usable: on another
/// OS, on a machine without TPM or with the TPM disabled in its firmware. This is said once, as a
/// warning. Keys created by the default store before a TPM became available stay readable: a key is
/// looked up in the TPM first, then in the default store.
/// </para>
/// <para>
/// CNG cannot enumerate keys without native calls, so each TPM key has a marker file next to where the
/// default store keeps its files (<c>-Local/CoreKeys/{name}.tpm</c>): that is what
/// <see cref="GetKeyNames"/> reads, and it shows an operator where a key is. CNG key names are
/// scoped by the owner's store folder, so that two stores on one machine never share a key.
/// </para>
/// <para>
/// Keys are created for the current user: the service must keep running under the same account.
/// </para>
/// </summary>
public sealed class TpmCoreKeyStore : ICoreKeyStore
{
    /// <summary>
    /// The CNG provider of the TPM.
    /// </summary>
    public const string PlatformProviderName = "Microsoft Platform Crypto Provider";

    const string MarkerExtension = ".tpm";

    readonly DefaultCoreKeyStore _fallback;
    readonly string _providerName;
    readonly CngProvider? _provider;
    readonly string? _unavailableReason;
    int _said;

    /// <summary>
    /// Initializes a store on the TPM, falling back to <paramref name="fallback"/> where no TPM is usable.
    /// </summary>
    /// <param name="fallback">The default store.</param>
    public TpmCoreKeyStore( DefaultCoreKeyStore fallback )
        : this( fallback, PlatformProviderName )
    {
    }

    /// <summary>
    /// Initializes a store on any CNG key storage provider. The tests use the software one: the same
    /// code path as the TPM, without the hardware.
    /// </summary>
    internal TpmCoreKeyStore( DefaultCoreKeyStore fallback, string providerName )
    {
        Throw.CheckNotNullArgument( fallback );
        _fallback = fallback;
        _providerName = providerName;
        if( !OperatingSystem.IsWindows() )
        {
            _unavailableReason = "the TPM is used through Windows CNG, and this is not Windows";
        }
        else
        {
            _provider = Probe( providerName, out _unavailableReason );
        }
    }

    /// <summary>
    /// Gets whether the provider is usable: when false, every key goes to the default store.
    /// </summary>
    public bool IsAvailable => _provider != null;

    /// <summary>
    /// Gets why the provider is not usable, null when it is.
    /// </summary>
    public string? UnavailableReason => _unavailableReason;

    [SupportedOSPlatform( "windows" )]
    static CngProvider? Probe( string providerName, out string? reason )
    {
        try
        {
            // An ephemeral key: nothing is left behind. This is what fails when the TPM is absent or
            // disabled ("The device that is required by this cryptographic provider is not ready").
            var provider = new CngProvider( providerName );
            using var k = CngKey.Create( CngAlgorithm.ECDsaP256, null, new CngKeyCreationParameters { Provider = provider } );
            reason = null;
            return provider;
        }
        catch( Exception ex )
        {
            reason = ex.Message;
            return null;
        }
    }

    /// <inheritdoc />
    public ReadOnlyMemory<byte> CreateKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        SayOnce( monitor );
        if( _provider == null || !OperatingSystem.IsWindows() ) return _fallback.CreateKey( monitor, owner, name );
        var marker = GetMarkerPath( owner, name );
        Throw.CheckState( $"Key '{name}' already exists for '{owner.FullName}'.",
                          !File.Exists( marker ) && !_fallback.GetKeyNames( monitor, owner ).Contains( name ) );
        var cngName = GetCngName( owner, name );
        // A key without its marker can only be left by a crash between the two: nothing refers to it.
        if( CngKey.Exists( cngName, _provider ) )
        {
            using var orphan = CngKey.Open( cngName, _provider );
            orphan.Delete();
        }
        using var key = CngKey.Create( CngAlgorithm.ECDsaP256, cngName, new CngKeyCreationParameters
        {
            Provider = _provider,
            // Not exportable: the private key never leaves the provider.
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None
        } );
        using var ecdsa = new ECDsaCng( key );
        var spki = ecdsa.ExportSubjectPublicKeyInfo();
        owner.LocalFileStore.CreateDirectory( marker.RemoveLastPart() );
        // The marker is written last: a key it names always exists.
        owner.LocalFileStore.WriteAllBytes( marker, Encoding.UTF8.GetBytes( $"{_providerName}\n{cngName}\n" ) );
        return spki;
    }

    /// <inheritdoc />
    public ECDsa? OpenKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        SayOnce( monitor );
        if( !File.Exists( GetMarkerPath( owner, name ) ) ) return _fallback.OpenKey( monitor, owner, name );
        if( _provider == null || !OperatingSystem.IsWindows() )
        {
            monitor.Error( $"Key '{name}' of '{owner.FullName}' is in the TPM, which is not usable: {_unavailableReason}" );
            return null;
        }
        var cngName = GetCngName( owner, name );
        try
        {
            if( !CngKey.Exists( cngName, _provider ) )
            {
                monitor.Error( $"Key '{name}' of '{owner.FullName}' should be in the TPM as '{cngName}', and is not there. " +
                               $"Was the TPM cleared, or does the service run under another account?" );
                return null;
            }
            return new ECDsaCng( CngKey.Open( cngName, _provider ) );
        }
        catch( Exception ex )
        {
            monitor.Error( $"Unable to open key '{name}' of '{owner.FullName}' in the TPM.", ex );
            return null;
        }
    }

    /// <inheritdoc />
    public bool DeleteKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        var marker = GetMarkerPath( owner, name );
        if( !File.Exists( marker ) ) return _fallback.DeleteKey( monitor, owner, name );
        if( _provider == null || !OperatingSystem.IsWindows() )
        {
            // The marker is kept: it is the only record of a key the TPM still holds.
            monitor.Error( $"Key '{name}' of '{owner.FullName}' is in the TPM, which is not usable: it cannot be destroyed now. {_unavailableReason}" );
            return false;
        }
        var cngName = GetCngName( owner, name );
        if( CngKey.Exists( cngName, _provider ) )
        {
            using var key = CngKey.Open( cngName, _provider );
            key.Delete();
        }
        owner.LocalFileStore.TryTrash( monitor, marker, immediateDelete: true );
        return true;
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GetKeyNames( IActivityMonitor monitor, ILocalParty owner )
    {
        var names = new List<string>( _fallback.GetKeyNames( monitor, owner ) );
        var folder = GetFolder( owner );
        if( Directory.Exists( folder ) )
        {
            names.AddRange( Directory.EnumerateFiles( folder, "*" + MarkerExtension ).Select( f => Path.GetFileNameWithoutExtension( f ) ) );
        }
        return names;
    }

    void SayOnce( IActivityMonitor monitor )
    {
        if( Interlocked.Exchange( ref _said, 1 ) != 0 ) return;
        if( _provider != null )
        {
            monitor.Info( $"Identity keys are created in '{_providerName}': not exportable." );
        }
        else
        {
            monitor.Warn( $"'{_providerName}' is not usable ({_unavailableReason}): identity keys go to the {nameof( DefaultCoreKeyStore )}." );
        }
    }

    static NormalizedPath GetFolder( ILocalParty owner ) => owner.LocalFileStore.FolderPath.AppendPart( DefaultCoreKeyStore.FolderName );

    static NormalizedPath GetMarkerPath( ILocalParty owner, string name )
    {
        Throw.CheckArgument( "A key name is 1 to 64 letters, digits, '-', '_' or '.', and does not start with '.'.",
                             !string.IsNullOrEmpty( name )
                             && name.Length <= 64
                             && name[0] != '.'
                             && name.All( c => char.IsAsciiLetterOrDigit( c ) || c == '-' || c == '_' || c == '.' ) );
        return GetFolder( owner ).AppendPart( name + MarkerExtension );
    }

    /// <summary>
    /// The CNG name of a key: scoped by the owner's store folder (hashed), so that two stores on one
    /// machine - two deployments, two test runs - never share a key of the same party name.
    /// </summary>
    internal static string GetCngName( ILocalParty owner, string name )
    {
        var scope = Convert.ToHexString( SHA256.HashData( Encoding.UTF8.GetBytes( owner.LocalFileStore.FolderPath.Path ) ), 0, 8 );
        return $"CK.AppIdentity.{scope}.{name}";
    }
}
