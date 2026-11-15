using CK.Core;
using Microsoft.Extensions.Configuration;
using System.Linq;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The "CngKeyStore" option of the KeyManagement feature: the identity keys of a local party are in a Windows CNG key
/// storage provider (see <see cref="CngCoreKeyStore"/>). Enabled by default: referencing this package says that the keys
/// must be in the provider; <c>"KeyManagement": { "CngKeyStore": false }</c> puts the keys of a party in files.
/// <code>
/// "KeyManagement": {
///   "CngKeyStore": {
///     "Provider": "Microsoft Platform Crypto Provider", // The default: the TPM.
///     "AllowFallback": false,                           // The default.
///     "MachineWide": false                              // The default.
///   }
/// }
/// </code>
/// An invalid configuration throws.
/// </summary>
[FeatureOption( IsEnabledByDefault = true )]
public sealed class CngKeyStoreOption : IPartyComponentOption<KeyManagementFeatureDriver>
{
    static readonly string[] _keys = ["Provider", "AllowFallback", "MachineWide"];

    /// <summary>
    /// Initializes a new <see cref="CngKeyStoreOption"/> from its configuration.
    /// </summary>
    /// <param name="configuration">The "CngKeyStore" section of the KeyManagement feature. Null for the defaults.</param>
    public CngKeyStoreOption( IConfiguration? configuration )
    {
        Provider = CngCoreKeyStore.DefaultProviderName;
        if( configuration != null )
        {
            foreach( var c in configuration.GetChildren() )
            {
                if( !_keys.Contains( c.Key ) ) Throw.CKException( $"Unknown \"{c.Key}\": the keys are {_keys.Concatenate()}." );
            }
            var provider = configuration["Provider"];
            if( provider != null )
            {
                if( string.IsNullOrWhiteSpace( provider ) ) Throw.CKException( "Invalid \"Provider\": a CNG provider name is expected." );
                Provider = provider;
            }
            AllowFallback = ReadBool( configuration, "AllowFallback" );
            MachineWide = ReadBool( configuration, "MachineWide" );
        }

        static bool ReadBool( IConfiguration c, string key )
        {
            var v = c[key];
            if( v == null ) return false;
            if( !bool.TryParse( v, out var b ) ) Throw.CKException( $"Invalid \"{key}\": '{v}' (true or false is expected)." );
            return b;
        }
    }

    /// <summary>
    /// Gets the CNG provider name. Defaults to <see cref="CngCoreKeyStore.DefaultProviderName"/> (the TPM).
    /// </summary>
    public string Provider { get; }

    /// <summary>
    /// Gets whether the keys go to the <see cref="DefaultCoreKeyStore"/> (with a warning) when the provider is not usable
    /// (another OS, no chip, a chip disabled in firmware, a missing driver). Defaults to false: an unusable provider stops
    /// the party from starting rather than silently downgrading to file keys. Set it in the "Defaults" of the root for a
    /// mixed fleet.
    /// </summary>
    public bool AllowFallback { get; }

    /// <summary>
    /// Gets whether the keys are CNG machine keys (default access: administrators and LocalSystem) instead of keys of the
    /// service account, for services whose account may change. Creating them in the TPM provider usually needs
    /// administrative rights. Defaults to false.
    /// </summary>
    public bool MachineWide { get; }
}
