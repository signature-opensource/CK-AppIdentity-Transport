using CK.Core;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Where the DataProtection key ring of the process lives and how it is protected at rest (see
/// <see cref="KeyManagementDataProtection"/>): in the private store of the root party, its <see cref="FolderName"/>
/// folder of its "-Local" (<see cref="ILocalParty.LocalFileStore"/>). The key ring follows the party: "#Dev/Store" in
/// development, the configured store in a deployment. The tenants of the process share it (each key has the purpose of
/// its party).
/// <para>
/// Its protection at rest, when the host doesn't choose one (decided at its first use, the first in this list wins):
/// <list type="number">
///   <item>a secret key, "Local:KeyManagement:KeyRingKey" of the root party (a secret: the base64 of 32 random bytes,
///   see <see cref="KeyKey"/>); "Local:KeyManagement:KeyRingPreviousKey" (a secret too) still decrypts what the previous
///   key encrypted, to change it;</item>
///   <item>the <see cref="ICoreKeyStore"/> when it is an <see cref="IKeyRingEncryptorSource"/>: the CNG store of
///   CK.AppIdentity.KeyManagement.Cng wraps the keys of the ring by a key of its provider (the TPM by default);</item>
///   <item>on Windows, DPAPI for the current account (as the default key ring of ASP.NET);</item>
///   <item>otherwise none: the ring is plain XML in the private store (restricted to the account). Outside "#Dev", this
///   is a warning.</item>
/// </list>
/// Each file of the ring records how it is protected: a change of protection only applies to the new keys of the ring
/// (DataProtection adds one every 90 days), the existing ones stay readable as long as their protection is available.
/// </para>
/// <para>
/// A host that persists the key ring itself (<c>PersistKeysToFileSystem</c>...) or protects it
/// (<c>ProtectKeysWithCertificate</c>...) keeps its choice.
/// </para>
/// <para>
/// <b>What it means:</b> the identity key files (<see cref="DefaultCoreKeyStore"/>) and the key ring are in the same
/// store: a copy of the store gives the keys away unless the ring is protected (a secret key kept apart, the TPM, or DPAPI
/// on the same computer and account).
/// </para>
/// </summary>
public static class KeyRingStore
{
    /// <summary>
    /// The folder of the key ring in the "-Local" of the root party: "DataProtection-Keys".
    /// </summary>
    public const string FolderName = "DataProtection-Keys";

    /// <summary>
    /// The path in the "Local" configuration of the root party of the secret key that protects the key ring:
    /// "KeyManagement:KeyRingKey" (a secret: the base64 of 32 random bytes).
    /// </summary>
    public const string KeyKey = "KeyManagement:KeyRingKey";

    /// <summary>
    /// The path in the "Local" configuration of the root party of the previous secret key of the key ring:
    /// "KeyManagement:KeyRingPreviousKey" (a secret). It only decrypts.
    /// </summary>
    public const string PreviousKeyKey = "KeyManagement:KeyRingPreviousKey";

    internal static void Register( IServiceCollection services )
    {
        services.AddSingleton<IPostConfigureOptions<KeyManagementOptions>, KeyRingConfiguration>();
    }

    // A secret key of the root party's configuration (a resolved secret once the host started), null when not configured:
    // read through the model of the "KeyManagement" feature, on the root party's own section.
    static byte[]? ReadSecretKey( ApplicationIdentityServiceConfiguration configuration, string key )
    {
        var section = configuration.LocalConfiguration.Configuration.TryGetSection( "KeyManagement" );
        if( section == null ) return null;
        var collector = new UserMessageCollector( new CurrentCultureInfo( new TranslationService(), NormalizedCultureInfo.CodeDefault ) );
        if( !ConfigurationModelReader.TryRead<KeyManagementConfiguration>( section, section.Path, collector, out var model ) )
        {
            throw new InvalidOperationException( $"Invalid \"{section.Path}\" of '{configuration.FullName}': "
                                                 + string.Join( " ", collector.UserMessages.Where( m => m.Level == UserMessageLevel.Error ).Select( m => m.Text ) ) );
        }
        var value = key == KeyKey ? model.KeyRingKey : model.KeyRingPreviousKey;
        if( string.IsNullOrWhiteSpace( value ) ) return null;
        byte[]? bytes = null;
        try
        {
            bytes = Convert.FromBase64String( value.Trim() );
        }
        catch( FormatException )
        {
        }
        if( bytes == null || bytes.Length != KeyRingCipher.KeyLength )
        {
            throw new InvalidOperationException( $"Invalid \"Local:{key}\" of '{configuration.FullName}': the base64 of {KeyRingCipher.KeyLength} random bytes is expected." );
        }
        return bytes;
    }

    // The 8 first bytes of the SHA-256 of a secret key, in hexadecimal: which key encrypted a file of the ring.
    static string GetKeyId( byte[] key ) => Convert.ToHexString( SHA256.HashData( key ).AsSpan( 0, 8 ) );

    sealed class KeyRingConfiguration : IPostConfigureOptions<KeyManagementOptions>
    {
        readonly ApplicationIdentityServiceConfiguration? _configuration;
        readonly IServiceProvider _services;
        readonly ILoggerFactory _loggerFactory;

        public KeyRingConfiguration( IServiceProvider services, ApplicationIdentityServiceConfiguration? configuration = null, ILoggerFactory? loggerFactory = null )
        {
            _configuration = configuration;
            _services = services;
            _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
        }

        public void PostConfigure( string? name, KeyManagementOptions options )
        {
            // Without an identity, there is no party store: the defaults of ASP.NET.
            // The host chose where the ring lives: it chose how it is protected too.
            if( _configuration == null || options.XmlRepository != null ) return;
            // An invalid secret key fails at start (the DataProtection is built by the KeyManagement driver), not when the
            // ring needs a new key, months later.
            ReadSecretKey( _configuration, KeyKey );
            ReadSecretKey( _configuration, PreviousKeyKey );
            options.XmlRepository = new LocalStoreXmlRepository( _services );
            options.XmlEncryptor ??= new DeferredXmlEncryptor( _services, _configuration, _loggerFactory );
        }
    }

    // The protection is chosen at the first use: the ApplicationIdentityService and the key store depend on the
    // DataProtection (they can't be resolved while its options are built).
    sealed class DeferredXmlEncryptor : IXmlEncryptor
    {
        readonly IServiceProvider _services;
        readonly ApplicationIdentityServiceConfiguration _configuration;
        readonly ILoggerFactory _loggerFactory;
        readonly object _lock = new object();
        IXmlEncryptor? _encryptor;

        public DeferredXmlEncryptor( IServiceProvider services, ApplicationIdentityServiceConfiguration configuration, ILoggerFactory loggerFactory )
        {
            _services = services;
            _configuration = configuration;
            _loggerFactory = loggerFactory;
        }

        public EncryptedXmlInfo Encrypt( XElement plaintextElement )
        {
            lock( _lock )
            {
                _encryptor ??= Choose();
            }
            return _encryptor.Encrypt( plaintextElement );
        }

        IXmlEncryptor Choose()
        {
            var monitor = new ActivityMonitor( $"The DataProtection key ring of '{_configuration.FullName}'." );
            try
            {
                var key = ReadSecretKey( _configuration, KeyKey );
                if( key != null )
                {
                    monitor.Info( $"The DataProtection key ring is encrypted by the secret key \"Local:{KeyKey}\"." );
                    return new SecretKeyXmlEncryptor( key );
                }
                if( _services.GetService<ICoreKeyStore>() is IKeyRingEncryptorSource source
                    && source.GetKeyRingEncryptor( monitor, _services.GetRequiredService<ApplicationIdentityService>() ) is IXmlEncryptor fromStore )
                {
                    return fromStore;
                }
                if( OperatingSystem.IsWindows() )
                {
                    monitor.Info( "The DataProtection key ring is encrypted by DPAPI for the current account." );
                    return new DpapiXmlEncryptor( protectToLocalMachine: false, _loggerFactory );
                }
                var message = $"The DataProtection key ring is not encrypted: it is plain XML in the private store of the party ('-Local/{FolderName}'), "
                              + $"with the identity key files. Configure \"Local:{KeyKey}\" (a secret) to encrypt it.";
                if( _configuration.EnvironmentName != CoreApplicationIdentity.DefaultEnvironmentName ) monitor.Warn( message );
                else monitor.Info( message );
                return new NullXmlEncryptor( _services );
            }
            finally
            {
                monitor.MonitorEnd();
            }
        }
    }

    sealed class SecretKeyXmlEncryptor : IXmlEncryptor
    {
        readonly byte[] _key;
        readonly string _id;

        public SecretKeyXmlEncryptor( byte[] key )
        {
            _key = key;
            _id = GetKeyId( key );
        }

        public EncryptedXmlInfo Encrypt( XElement plaintextElement )
        {
            var e = new XElement( "encryptedKey",
                                  new XComment( " This key is encrypted by the secret key \"Local:KeyManagement:KeyRingKey\" (AES-256-GCM). " ),
                                  new XElement( "secret", new XAttribute( "id", _id ) ),
                                  new XElement( "value", KeyRingCipher.Seal( plaintextElement, _key ) ) );
            return new EncryptedXmlInfo( e, typeof( SecretKeyXmlDecryptor ) );
        }
    }

    /// <summary>
    /// Decrypts the files of the key ring encrypted by the secret key "Local:KeyManagement:KeyRingKey" (or the previous one,
    /// "Local:KeyManagement:KeyRingPreviousKey") of the root party. Instantiated by the DataProtection.
    /// </summary>
    public sealed class SecretKeyXmlDecryptor : IXmlDecryptor
    {
        readonly ApplicationIdentityServiceConfiguration? _configuration;

        /// <summary>
        /// Initializes a decryptor.
        /// </summary>
        /// <param name="services">The services of the application.</param>
        public SecretKeyXmlDecryptor( IServiceProvider services )
        {
            _configuration = services.GetService<ApplicationIdentityServiceConfiguration>();
        }

        /// <inheritdoc />
        public XElement Decrypt( XElement encryptedElement )
        {
            Throw.CheckNotNullArgument( encryptedElement );
            var id = (string?)encryptedElement.Element( "secret" )?.Attribute( "id" );
            var value = (string?)encryptedElement.Element( "value" );
            if( id == null || value == null ) throw new CryptographicException( "Invalid key ring element: <secret id=\"...\"/> and <value> are expected." );
            if( _configuration == null ) throw new CryptographicException( "No application identity configuration: the secret key of the key ring is unknown." );
            foreach( var k in new[] { KeyKey, PreviousKeyKey } )
            {
                var key = ReadSecretKey( _configuration, k );
                if( key != null && GetKeyId( key ) == id ) return KeyRingCipher.Open( value, key );
            }
            throw new CryptographicException( $"This key of the key ring was encrypted by a secret key '{id}' that is neither \"Local:{KeyKey}\" nor \"Local:{PreviousKeyKey}\" of '{_configuration.FullName}'." );
        }
    }

    // The ring in the root party's "-Local": resolved at the first use (the ApplicationIdentityService depends on the
    // DataProtection through its drivers).
    sealed class LocalStoreXmlRepository : IXmlRepository
    {
        readonly IServiceProvider _services;
        readonly object _lock = new object();
        IFileStore? _store;

        public LocalStoreXmlRepository( IServiceProvider services ) => _services = services;

        IFileStore Store => _store ??= _services.GetRequiredService<ApplicationIdentityService>().LocalFileStore;

        NormalizedPath Folder => Store.FolderPath.AppendPart( FolderName );

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            lock( _lock )
            {
                var folder = Folder;
                if( !Directory.Exists( folder ) ) return Array.Empty<XElement>();
                var result = new List<XElement>();
                foreach( var f in Directory.EnumerateFiles( folder, "*.xml" ).Order( StringComparer.Ordinal ) )
                {
                    using var s = Store.OpenReadStream( f );
                    result.Add( XElement.Load( s ) );
                }
                return result;
            }
        }

        public void StoreElement( XElement element, string friendlyName )
        {
            lock( _lock )
            {
                var folder = Folder;
                Store.CreateDirectory( folder );
                var file = folder.AppendPart( IsSafeFileName( friendlyName ) ? $"{friendlyName}.xml" : $"{Guid.NewGuid():D}.xml" );
                Store.WriteAtomically( file, s => element.Save( s ) );
            }
        }

        // The friendly name is "key-{guid}": anything else gets a new name.
        static bool IsSafeFileName( string? name ) => !string.IsNullOrEmpty( name )
                                                      && name.Length <= 100
                                                      && name[0] != '.'
                                                      && name.All( c => char.IsAsciiLetterOrDigit( c ) || c == '-' || c == '_' );
    }
}
