using CK.Core;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// An <see cref="ICoreKeyStore"/> that keeps the identity keys in a Windows CNG key storage provider: by
/// default the TPM ("Microsoft Platform Crypto Provider"), or any provider an HSM or a smart card vendor
/// ships. Keys are created inside the provider, are not exportable, and every signature is made by it:
/// a host that is copied, backed up or stolen gives up no key.
/// <para>
/// What it does not prevent: an attacker running code on the host while it is compromised can USE the
/// keys (but never take them away). That is what the offline recovery key is for
/// (<see cref="ILocalKeys.Recover"/>).
/// </para>
/// <para>
/// <b>Configuration</b>, per local party, looked up from the party up through its parents (so a value at
/// the root applies to every tenant domain, which may override it):
/// <list type="bullet">
///   <item><c>CoreKeyStore:CngProvider</c>: the provider name. Defaults to <see cref="DefaultProviderName"/>.</item>
///   <item><c>CoreKeyStore:AllowFallback</c>: when true and the provider is not usable (another OS, no
///   chip, a chip disabled in firmware, a missing driver), keys go to the <see cref="DefaultCoreKeyStore"/>
///   with a warning. <b>Defaults to false</b>: referencing this package says that keys must be in
///   hardware, and an unusable provider then refuses the party's startup rather than silently
///   downgrading to file keys. Set it at the root for a mixed fleet.</item>
///   <item><c>CoreKeyStore:MachineWide</c>: when true, keys belong to the machine instead of the
///   service account (CNG machine keys: default access is administrators and LocalSystem), for services
///   whose account may change. Creating them in the TPM provider usually needs administrative rights.
///   Defaults to false: keys of the current user.</item>
/// </list>
/// </para>
/// <para>
/// <b>Each key remembers where it is.</b> CNG cannot enumerate keys without native calls, so each key
/// has a marker file next to where the default store keeps its files (<c>-Local/CoreKeys/{name}.cng</c>)
/// that records its provider and scope. Opening and destroying a key use the marker, never the current
/// configuration: changing the provider orphans nothing, new keys go to the new one and the next rotation
/// moves the identity across. Keys of the default store (created before this store, or under
/// <c>AllowFallback</c>) stay readable the same way.
/// </para>
/// <para>
/// It covers the <see cref="DefaultCoreKeyStore"/> (its constructor parameter), which is how the
/// automatic DI makes it replace the default store.
/// </para>
/// </summary>
public sealed class CngCoreKeyStore : ICoreKeyStore
{
    /// <summary>
    /// The CNG provider of the TPM: the default <c>CoreKeyStore:CngProvider</c>.
    /// </summary>
    public const string DefaultProviderName = "Microsoft Platform Crypto Provider";

    const string MarkerExtension = ".cng";

    readonly DefaultCoreKeyStore _fallback;
    // Probed once per provider name: creating an ephemeral key is what fails when the provider is absent
    // or not ready, and on a TPM it costs a round trip to the chip.
    readonly ConcurrentDictionary<string, (CngProvider? Provider, string? Reason)> _probes;
    readonly ConditionalWeakTable<ILocalParty, Settings> _settings;

    sealed record Settings( string ProviderName, bool AllowFallback, bool MachineWide )
    {
        public bool FallbackSaid;
    }

    /// <summary>
    /// Initializes a CNG store, covering the default one.
    /// </summary>
    /// <param name="fallback">The default store.</param>
    public CngCoreKeyStore( DefaultCoreKeyStore fallback )
    {
        Throw.CheckNotNullArgument( fallback );
        _fallback = fallback;
        _probes = new ConcurrentDictionary<string, (CngProvider?, string?)>( StringComparer.OrdinalIgnoreCase );
        _settings = new ConditionalWeakTable<ILocalParty, Settings>();
    }

    /// <summary>
    /// Gets whether a CNG provider is usable on this machine, for this account.
    /// </summary>
    /// <param name="providerName">The provider name.</param>
    /// <param name="reason">Outputs why it is not, null when it is.</param>
    /// <returns>True if keys can be created in it.</returns>
    public bool IsUsable( string providerName, out string? reason )
    {
        var p = Probe( providerName );
        reason = p.Reason;
        return p.Provider != null;
    }

    (CngProvider? Provider, string? Reason) Probe( string providerName )
    {
        return _probes.GetOrAdd( providerName, static name =>
        {
            if( !OperatingSystem.IsWindows() ) return (null, "CNG key storage providers exist only on Windows");
            return ProbeOnWindows( name );
        } );
    }

    [SupportedOSPlatform( "windows" )]
    static (CngProvider?, string?) ProbeOnWindows( string name )
    {
        try
        {
            var provider = new CngProvider( name );
            // An ephemeral key: nothing is left behind.
            using var k = CngKey.Create( CngAlgorithm.ECDsaP256, null, new CngKeyCreationParameters { Provider = provider } );
            return (provider, null);
        }
        catch( Exception ex )
        {
            return (null, ex.Message);
        }
    }

    Settings GetSettings( IActivityMonitor monitor, ILocalParty owner )
    {
        return _settings.GetValue( owner, o =>
        {
            var c = o.Configuration.Configuration;
            var providerName = c.TryLookupValue( "CoreKeyStore:CngProvider" ) ?? DefaultProviderName;
            return new Settings( providerName, ReadBool( c, "CoreKeyStore:AllowFallback" ), ReadBool( c, "CoreKeyStore:MachineWide" ) );

            bool ReadBool( ImmutableConfigurationSection c, string key )
            {
                var v = c.TryLookupValue( key );
                if( v == null ) return false;
                if( bool.TryParse( v, out var b ) ) return b;
                monitor.Warn( $"Invalid '{c.Path}:{key}' = '{v}': expected 'true' or 'false', using false." );
                return false;
            }
        } );
    }

    /// <summary>
    /// The provider to create keys in for <paramref name="owner"/>, or null when keys go to the default
    /// store (provider not usable and fallback allowed). Throws when the provider is required and not usable.
    /// </summary>
    CngProvider? GetCreationProvider( IActivityMonitor monitor, ILocalParty owner, Settings s )
    {
        var (provider, reason) = Probe( s.ProviderName );
        if( provider != null ) return provider;
        if( !s.AllowFallback )
        {
            Throw.CKException( $"The CNG provider '{s.ProviderName}' is not usable for '{owner.FullName}': {reason}. " +
                               $"Identity keys must be in it. Set 'CoreKeyStore:AllowFallback' to true to accept keys " +
                               $"in files ({nameof( DefaultCoreKeyStore )}) where it is not usable." );
        }
        if( !s.FallbackSaid )
        {
            s.FallbackSaid = true;
            monitor.Warn( $"The CNG provider '{s.ProviderName}' is not usable for '{owner.FullName}' ({reason}): " +
                          $"its identity keys go to the {nameof( DefaultCoreKeyStore )} ('CoreKeyStore:AllowFallback' is true)." );
        }
        return null;
    }

    /// <inheritdoc />
    public ReadOnlyMemory<byte> CreateKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        var marker = GetMarkerPath( owner, name );
        var s = GetSettings( monitor, owner );
        var provider = GetCreationProvider( monitor, owner, s );
        if( provider == null || !OperatingSystem.IsWindows() ) return _fallback.CreateKey( monitor, owner, name );
        Throw.CheckState( $"Key '{name}' already exists for '{owner.FullName}'.",
                          !File.Exists( marker ) && !_fallback.GetKeyNames( monitor, owner ).Contains( name ) );
        var cngName = GetCngName( owner, name );
        var openOptions = s.MachineWide ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        // A key without its marker can only be left by a crash between the two: nothing refers to it.
        if( CngKey.Exists( cngName, provider, openOptions ) )
        {
            using var orphan = CngKey.Open( cngName, provider, openOptions );
            orphan.Delete();
        }
        using var key = CngKey.Create( CngAlgorithm.ECDsaP256, cngName, new CngKeyCreationParameters
        {
            Provider = provider,
            // Not exportable: the private key never leaves the provider.
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = s.MachineWide ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None
        } );
        using var ecdsa = new ECDsaCng( key );
        var spki = ecdsa.ExportSubjectPublicKeyInfo();
        owner.LocalFileStore.CreateDirectory( marker.RemoveLastPart() );
        // The marker is written last: a key it names always exists.
        owner.LocalFileStore.WriteAllBytes( marker, new Marker( provider.Provider, s.MachineWide, cngName ).Encode() );
        return spki;
    }

    /// <inheritdoc />
    public ECDsa? OpenKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        var markerPath = GetMarkerPath( owner, name );
        var s = GetSettings( monitor, owner );
        if( !File.Exists( markerPath ) )
        {
            // A key of the default store. Readable, unless keys are required in a provider that is not
            // usable: then this party must not run on file keys at all.
            GetCreationProvider( monitor, owner, s );
            return _fallback.OpenKey( monitor, owner, name );
        }
        var m = Marker.Read( owner, markerPath );
        var (provider, reason) = Probe( m.ProviderName );
        if( provider == null || !OperatingSystem.IsWindows() )
        {
            monitor.Error( $"Key '{name}' of '{owner.FullName}' is in the CNG provider '{m.ProviderName}', which is not usable: {reason}" );
            return null;
        }
        var options = m.MachineWide ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        try
        {
            if( !CngKey.Exists( m.CngName, provider, options ) )
            {
                monitor.Error( $"Key '{name}' of '{owner.FullName}' should be in '{m.ProviderName}' as '{m.CngName}' and is not there. " +
                               $"Was the provider cleared, or does the service run under another account?" );
                return null;
            }
            return new ECDsaCng( CngKey.Open( m.CngName, provider, options ) );
        }
        catch( Exception ex )
        {
            monitor.Error( $"Unable to open key '{name}' of '{owner.FullName}' in '{m.ProviderName}'.", ex );
            return null;
        }
    }

    /// <inheritdoc />
    public bool DeleteKey( IActivityMonitor monitor, ILocalParty owner, string name )
    {
        var markerPath = GetMarkerPath( owner, name );
        if( !File.Exists( markerPath ) ) return _fallback.DeleteKey( monitor, owner, name );
        var m = Marker.Read( owner, markerPath );
        var (provider, reason) = Probe( m.ProviderName );
        if( provider == null || !OperatingSystem.IsWindows() )
        {
            // The marker is kept: it is the only record of a key the provider still holds.
            monitor.Error( $"Key '{name}' of '{owner.FullName}' is in '{m.ProviderName}', which is not usable: it cannot be destroyed now. {reason}" );
            return false;
        }
        var options = m.MachineWide ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        if( CngKey.Exists( m.CngName, provider, options ) )
        {
            using var key = CngKey.Open( m.CngName, provider, options );
            key.Delete();
        }
        owner.LocalFileStore.TryTrash( monitor, markerPath, immediateDelete: true );
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

    /// <summary>
    /// Where a key is: its provider, its scope and its CNG name. One line each, readable by an operator.
    /// </summary>
    sealed record Marker( string ProviderName, bool MachineWide, string CngName )
    {
        public byte[] Encode() => Encoding.UTF8.GetBytes( $"{ProviderName}\n{(MachineWide ? "machine" : "user")}\n{CngName}\n" );

        public static Marker Read( ILocalParty owner, NormalizedPath path )
        {
            string text;
            // Read through the store: it opens with FileShare.Delete, so a reader never blocks a replacement.
            using( var s = owner.LocalFileStore.OpenReadStream( path ) )
            using( var r = new StreamReader( s, Encoding.UTF8 ) )
            {
                text = r.ReadToEnd();
            }
            var lines = text.Split( '\n', StringSplitOptions.RemoveEmptyEntries );
            Throw.CheckData( $"Invalid key marker '{path}'.", lines.Length == 3 && (lines[1] == "machine" || lines[1] == "user") );
            return new Marker( lines[0], lines[1] == "machine", lines[2] );
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
