using CK.AppIdentity.KeyManagement;
using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The encryption keys of a local Authentication Center (ECDH P-256): its remotes encrypt the sensitive fields of the
/// commands they send to it with the current one (see <see cref="AuthCenterFieldEncryption"/>).
/// <para>
/// A key is used for <see cref="Lifetime"/> (a new one is created <see cref="Grace"/> before its end) and kept for
/// <see cref="Grace"/> more, for the fields encrypted just before. Keys are persisted in the <see cref="ILocalParty.LocalFileStore"/>
/// ("AuthCenter/EncryptionKeys"), protected by the local party's data protector. The public key is published signed by the
/// Authentication Center for the <see cref="Purpose"/>.
/// </para>
/// </summary>
sealed class AuthCenterEncryptionKeys
{
    /// <summary>
    /// The purpose of the signature of a published key.
    /// </summary>
    internal const string Purpose = AuthCenterFieldEncryption.EncryptionKeyPurpose;

    /// <summary>
    /// How long a key is published: 1 day.
    /// </summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromDays( 1 );

    /// <summary>
    /// The overlap between two keys: 10 minutes.
    /// </summary>
    internal static readonly TimeSpan Grace = TimeSpan.FromMinutes( 10 );

    sealed class Key
    {
        public required byte[] Id { get; init; }
        public required ECDiffieHellman Private { get; init; }
        public required byte[] Spki { get; init; }
        public required DateTime Created { get; init; }
        public required NormalizedPath Path { get; init; }
        public DateTime Expires => Created + Lifetime;
        public (string Signature, string PublicKey)? Published;
    }

    readonly ILocalParty _party;
    readonly IFileStore _store;
    readonly NormalizedPath _folder;
    readonly IDataProtector _protector;
    readonly object _lock;
    readonly List<Key> _keys;

    internal AuthCenterEncryptionKeys( IActivityMonitor monitor, ILocalParty party )
    {
        _party = party;
        _store = party.LocalFileStore;
        _folder = _store.FolderPath.Combine( "AuthCenter/EncryptionKeys" );
        _protector = party.GetRequiredFeature<ILocalKeys>().Protector.CreateProtector( Purpose );
        _lock = new object();
        _keys = new List<Key>();
        if( Directory.Exists( _folder ) )
        {
            foreach( var file in Directory.EnumerateFiles( _folder ) )
            {
                var k = TryLoad( monitor, file );
                if( k != null ) _keys.Add( k );
                else _store.TryTrash( monitor, file, immediateDelete: true );
            }
            _keys.Sort( ( a, b ) => a.Created.CompareTo( b.Created ) );
        }
    }

    Key? TryLoad( IActivityMonitor monitor, NormalizedPath path )
    {
        try
        {
            byte[] protectedBytes;
            using( var s = _store.OpenReadStream( path ) )
            using( var m = new MemoryStream() )
            {
                s.CopyTo( m );
                protectedBytes = m.ToArray();
            }
            var bytes = _protector.Unprotect( protectedBytes );
            try
            {
                var created = new DateTime( BinaryPrimitives.ReadInt64BigEndian( bytes ), DateTimeKind.Utc );
                var key = ECDiffieHellman.Create();
                key.ImportPkcs8PrivateKey( bytes.AsSpan( 8 ), out _ );
                var spki = key.ExportSubjectPublicKeyInfo();
                return new Key { Id = AuthCenterFieldEncryption.GetKeyId( spki ), Private = key, Spki = spki, Created = created, Path = path };
            }
            finally
            {
                CryptographicOperations.ZeroMemory( bytes );
            }
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to load the AuthCenter encryption key '{path}': it is deleted.", ex );
            return null;
        }
    }

    Key Create( DateTime utcNow )
    {
        var key = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        var spki = key.ExportSubjectPublicKeyInfo();
        var id = AuthCenterFieldEncryption.GetKeyId( spki );
        var pkcs8 = key.ExportPkcs8PrivateKey();
        var bytes = new byte[8 + pkcs8.Length];
        BinaryPrimitives.WriteInt64BigEndian( bytes, utcNow.Ticks );
        pkcs8.CopyTo( bytes.AsSpan( 8 ) );
        var path = _folder.AppendPart( Convert.ToHexString( id ).ToLowerInvariant() + ".key" );
        try
        {
            var protectedBytes = _protector.Protect( bytes );
            _store.CreateDirectory( _folder );
            _store.WriteAtomically( path, s => s.Write( protectedBytes ) );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( pkcs8 );
            CryptographicOperations.ZeroMemory( bytes );
        }
        return new Key { Id = id, Private = key, Spki = spki, Created = utcNow, Path = path };
    }

    // Must be called under the lock: drops the keys that cannot be used anymore.
    void Prune( IActivityMonitor monitor, DateTime utcNow )
    {
        while( _keys.Count > 0 && _keys[0].Expires + Grace <= utcNow )
        {
            var k = _keys[0];
            _keys.RemoveAt( 0 );
            k.Private.Dispose();
            _store.TryTrash( monitor, k.Path, immediateDelete: true );
        }
    }

    /// <summary>
    /// Gets the current public key, signed (a new key is created when the current one ends in less than <see cref="Grace"/>).
    /// </summary>
    internal (string PublicKey, string Signature) GetPublished( IActivityMonitor monitor, ILocalKeys signer, DateTime utcNow )
    {
        lock( _lock )
        {
            Prune( monitor, utcNow );
            if( _keys.Count == 0 || _keys[^1].Expires - Grace <= utcNow )
            {
                _keys.Add( Create( utcNow ) );
                monitor.Info( $"New AuthCenter encryption key for '{_party}'." );
            }
            var k = _keys[^1];
            k.Published ??= (System.Buffers.Text.Base64Url.EncodeToString( signer.Sign( Purpose, k.Spki, k.Expires ).Encoded.Span ),
                             System.Buffers.Text.Base64Url.EncodeToString( k.Spki ));
            return (k.Published.Value.PublicKey, k.Published.Value.Signature);
        }
    }

    /// <summary>
    /// Finds a private key by its identifier (it can still be used: its end plus <see cref="Grace"/> is not reached).
    /// </summary>
    internal ECDiffieHellman? Find( byte[] keyId, DateTime utcNow )
    {
        lock( _lock )
        {
            foreach( var k in _keys )
            {
                if( k.Id.AsSpan().SequenceEqual( keyId ) && k.Expires + Grace > utcNow ) return k.Private;
            }
            return null;
        }
    }
}
