using CK.Core;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace CK.AppIdentity.KeyManagement;

public sealed partial class CngCoreKeyStore : IKeyRingEncryptorSource
{
    /// <summary>
    /// The name of the key of the provider that protects the DataProtection key ring, for <see cref="GetCngName"/>: "KeyRing".
    /// </summary>
    const string KeyRingKeyName = "KeyRing";

    /// <summary>
    /// The DataProtection key ring of the process (see <see cref="KeyRingStore"/>) is protected by the provider of the root
    /// party (its <see cref="CngKeyStoreOption"/>): each file of the ring is encrypted by a fresh content key
    /// (<see cref="KeyRingCipher"/>), wrapped by a non-exportable RSA key of the provider (RSA-OAEP: SHA-256 when the
    /// provider decrypts with it, SHA-1 otherwise; the file records it). The ring is then bound to the provider (the TPM by
    /// default: this computer), as the identity keys are.
    /// <para>
    /// Null (the next protection applies: DPAPI) when the option of the root party is disabled, or when its provider is not
    /// usable and "AllowFallback" is true; an unusable provider without fallback throws (as for the identity keys).
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="root">The root party.</param>
    /// <returns>The encryptor or null.</returns>
    public IXmlEncryptor? GetKeyRingEncryptor( IActivityMonitor monitor, ILocalParty root )
    {
        Throw.CheckNotNullArgument( monitor );
        Throw.CheckNotNullArgument( root );
        var s = GetSettings( root );
        if( s == null || !OperatingSystem.IsWindows() ) return null;
        var provider = GetCreationProvider( monitor, root, s );
        if( provider == null )
        {
            monitor.Info( $"The DataProtection key ring of '{root.FullName}' is not protected by the CNG provider '{s.ProviderName}' (not usable, 'AllowFallback' is true)." );
            return null;
        }
        var encryptor = CreateKeyRingEncryptor( provider, s.MachineWide, GetCngName( root, KeyRingKeyName ) );
        monitor.Info( $"The DataProtection key ring of '{root.FullName}' is protected by the CNG provider '{s.ProviderName}' (key '{encryptor.KeyName}', OAEP-{encryptor.Padding})." );
        return encryptor;
    }

    [SupportedOSPlatform( "windows" )]
    static KeyRingXmlEncryptor CreateKeyRingEncryptor( CngProvider provider, bool machineWide, string keyName )
    {
        var openOptions = machineWide ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        using var key = CngKey.Exists( keyName, provider, openOptions )
                        ? CngKey.Open( keyName, provider, openOptions )
                        : CngKey.Create( CngAlgorithm.Rsa, keyName, new CngKeyCreationParameters
                        {
                            Provider = provider,
                            // Not exportable: the private key never leaves the provider.
                            ExportPolicy = CngExportPolicies.None,
                            KeyUsage = CngKeyUsages.Decryption,
                            KeyCreationOptions = machineWide ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None,
                            Parameters = { new CngProperty( "Length", BitConverter.GetBytes( 2048 ), CngPropertyOptions.None ) }
                        } );
        using var rsa = new RSACng( key );
        // The padding the provider decrypts with: OAEP-SHA-256 is not supported by every TPM.
        var padding = "SHA256";
        try
        {
            var probe = RandomNumberGenerator.GetBytes( KeyRingCipher.KeyLength );
            if( !rsa.Decrypt( rsa.Encrypt( probe, RSAEncryptionPadding.OaepSHA256 ), RSAEncryptionPadding.OaepSHA256 ).AsSpan().SequenceEqual( probe ) )
            {
                padding = "SHA1";
            }
        }
        catch( CryptographicException )
        {
            padding = "SHA1";
        }
        return new KeyRingXmlEncryptor( provider.Provider, machineWide, keyName, padding, rsa.ExportParameters( includePrivateParameters: false ) );
    }

    static RSAEncryptionPadding GetPadding( string? name ) => name switch
    {
        "SHA256" => RSAEncryptionPadding.OaepSHA256,
        "SHA1" => RSAEncryptionPadding.OaepSHA1,
        _ => throw new CryptographicException( $"Invalid key ring element: unknown padding '{name}'." )
    };

    sealed class KeyRingXmlEncryptor : IXmlEncryptor
    {
        readonly string _providerName;
        readonly bool _machineWide;
        readonly RSAParameters _publicKey;

        public KeyRingXmlEncryptor( string providerName, bool machineWide, string keyName, string padding, RSAParameters publicKey )
        {
            _providerName = providerName;
            _machineWide = machineWide;
            KeyName = keyName;
            Padding = padding;
            _publicKey = publicKey;
        }

        public string KeyName { get; }

        public string Padding { get; }

        public EncryptedXmlInfo Encrypt( XElement plaintextElement )
        {
            var contentKey = RandomNumberGenerator.GetBytes( KeyRingCipher.KeyLength );
            try
            {
                // Encrypting needs the public key only: no round trip to the provider.
                using var rsa = RSA.Create( _publicKey );
                var wrapped = rsa.Encrypt( contentKey, GetPadding( Padding ) );
                var e = new XElement( "encryptedKey",
                                      new XComment( " This key is encrypted by a content key wrapped by a key of a CNG provider (AES-256-GCM, RSA-OAEP). " ),
                                      new XElement( "cng",
                                                    new XAttribute( "provider", _providerName ),
                                                    new XAttribute( "scope", _machineWide ? "machine" : "user" ),
                                                    new XAttribute( "key", KeyName ),
                                                    new XAttribute( "padding", Padding ) ),
                                      new XElement( "wrappedKey", Convert.ToBase64String( wrapped ) ),
                                      new XElement( "value", KeyRingCipher.Seal( plaintextElement, contentKey ) ) );
                return new EncryptedXmlInfo( e, typeof( CngKeyRingXmlDecryptor ) );
            }
            finally
            {
                CryptographicOperations.ZeroMemory( contentKey );
            }
        }
    }

    /// <summary>
    /// Decrypts the files of the DataProtection key ring protected by a key of a CNG provider (see
    /// <see cref="GetKeyRingEncryptor(IActivityMonitor, ILocalParty)"/>): each file names its provider, its scope and its
    /// key. Instantiated by the DataProtection.
    /// </summary>
    public sealed class CngKeyRingXmlDecryptor : IXmlDecryptor
    {
        /// <inheritdoc />
        public XElement Decrypt( XElement encryptedElement )
        {
            Throw.CheckNotNullArgument( encryptedElement );
            if( !OperatingSystem.IsWindows() ) throw new PlatformNotSupportedException( "This key of the key ring is protected by a CNG provider: it can only be read on Windows." );
            var cng = encryptedElement.Element( "cng" );
            var providerName = (string?)cng?.Attribute( "provider" );
            var scope = (string?)cng?.Attribute( "scope" );
            var keyName = (string?)cng?.Attribute( "key" );
            var wrapped = (string?)encryptedElement.Element( "wrappedKey" );
            var value = (string?)encryptedElement.Element( "value" );
            if( providerName == null || keyName == null || wrapped == null || value == null || (scope != "user" && scope != "machine") )
            {
                throw new CryptographicException( "Invalid key ring element: <cng provider=\"...\" scope=\"user|machine\" key=\"...\" padding=\"...\"/>, <wrappedKey> and <value> are expected." );
            }
            return Decrypt( providerName, scope == "machine", keyName, GetPadding( (string?)cng!.Attribute( "padding" ) ), wrapped, value );
        }

        [SupportedOSPlatform( "windows" )]
        static XElement Decrypt( string providerName, bool machineWide, string keyName, RSAEncryptionPadding padding, string wrapped, string value )
        {
            var provider = new CngProvider( providerName );
            var options = machineWide ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
            if( !CngKey.Exists( keyName, provider, options ) )
            {
                throw new CryptographicException( $"This key of the key ring is protected by the key '{keyName}' of the CNG provider '{providerName}', which is not there. "
                                                  + "Was the provider cleared, is it another computer, or does the service run under another account?" );
            }
            using var key = CngKey.Open( keyName, provider, options );
            using var rsa = new RSACng( key );
            var contentKey = rsa.Decrypt( Convert.FromBase64String( wrapped ), padding );
            try
            {
                return KeyRingCipher.Open( value, contentKey );
            }
            finally
            {
                CryptographicOperations.ZeroMemory( contentKey );
            }
        }
    }
}
