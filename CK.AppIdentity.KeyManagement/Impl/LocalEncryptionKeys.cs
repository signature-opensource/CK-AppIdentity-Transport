using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The encryption keys of a local party (ECDH P-256, see <see cref="PartyEncryption"/>): the other parties encrypt for it
/// with the current one, that it publishes in its description.
/// <para>
/// A key is used for <see cref="PartyEncryption.KeyLifetime"/> (a new one is created <see cref="PartyEncryption.KeyOverlap"/>
/// before its end) and kept for <see cref="PartyEncryption.KeyOverlap"/> more, for what has been encrypted just before.
/// Keys are persisted in the <see cref="ILocalParty.LocalFileStore"/> ("KeyManagement/EncryptionKeys"), protected by the
/// local party's data protector. The public key is published signed by the party for the <see cref="PartyEncryption.KeyPurpose"/>.
/// </para>
/// <para>
/// The current key is the last one created at or before now: a key created in the future (the clock went backwards) is
/// kept to decrypt what was encrypted for it, it becomes current only at its creation date.
/// </para>
/// </summary>
sealed class LocalEncryptionKeys
{
    /// <summary>
    /// The folder of the keys in the private store of their party.
    /// </summary>
    internal const string FolderPath = "KeyManagement/EncryptionKeys";

    sealed class Key
    {
        public required byte[] Id { get; init; }
        public required ECDiffieHellman Private { get; init; }
        public required byte[] Spki { get; init; }
        public required DateTime Created { get; init; }
        public required NormalizedPath Path { get; init; }
        public DateTime Expires => Created + PartyEncryption.KeyLifetime;
        public PartyEncryptionKey? Published;
    }

    readonly ILocalParty _party;
    readonly IFileStore _store;
    readonly NormalizedPath _folder;
    readonly IDataProtector _protector;
    readonly object _lock;
    readonly List<Key> _keys;

    internal LocalEncryptionKeys( IActivityLineEmitter logger, ILocalParty party, IDataProtector protector )
    {
        _party = party;
        _store = party.LocalFileStore;
        _folder = _store.FolderPath.Combine( FolderPath );
        _protector = protector.CreateProtector( PartyEncryption.KeyPurpose );
        _lock = new object();
        _keys = new List<Key>();
        if( Directory.Exists( _folder ) )
        {
            foreach( var file in Directory.GetFiles( _folder ) )
            {
                var k = TryLoad( logger, file, out bool invalid );
                if( k != null ) _keys.Add( k );
                else if( invalid ) _store.TryTrash( logger, file, immediateDelete: true );
            }
            _keys.Sort( ( a, b ) => a.Created.CompareTo( b.Created ) );
            var now = party.ApplicationIdentityService.SystemClock.UtcNow;
            foreach( var k in _keys )
            {
                if( k.Created > now )
                {
                    logger.Warn( $"The encryption key '{k.Path}' of '{party}' was created in the future ({k.Created:O}, the clock went backwards): it is kept to decrypt what was encrypted for it, it is not published before its creation date." );
                }
            }
        }
    }

    // Only an invalid key file is deleted: a key that can't be read now (an IO error) or that is gone (another
    // instance of this party trashed it) is not. Deleting a readable key loses the data it encrypts.
    Key? TryLoad( IActivityLineEmitter logger, NormalizedPath path, out bool invalid )
    {
        invalid = false;
        byte[]? protectedBytes;
        try
        {
            protectedBytes = _store.TryReadAllBytes( path );
        }
        catch( Exception ex )
        {
            logger.Warn( $"Unable to read the encryption key '{path}': it is not used (and kept).", ex );
            return null;
        }
        if( protectedBytes == null ) return null;
        try
        {
            var bytes = _protector.Unprotect( protectedBytes );
            try
            {
                var created = new DateTime( BinaryPrimitives.ReadInt64BigEndian( bytes ), DateTimeKind.Utc );
                var key = ECDiffieHellman.Create();
                key.ImportPkcs8PrivateKey( bytes.AsSpan( 8 ), out _ );
                var spki = key.ExportSubjectPublicKeyInfo();
                return new Key { Id = PartyEncryption.GetKeyId( spki ), Private = key, Spki = spki, Created = created, Path = path };
            }
            finally
            {
                CryptographicOperations.ZeroMemory( bytes );
            }
        }
        catch( Exception ex )
        {
            // A file that can't be unprotected is invalid, even when the cause is the data protection key ring (lost
            // or changed) rather than the file: such a key is useless and it is deleted. This is accepted.
            logger.Warn( $"Invalid encryption key '{path}': it is deleted.", ex );
            invalid = true;
            return null;
        }
    }

    Key Create( DateTime utcNow )
    {
        var key = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        var spki = key.ExportSubjectPublicKeyInfo();
        var id = PartyEncryption.GetKeyId( spki );
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
    void Prune( IActivityLineEmitter logger, DateTime utcNow )
    {
        while( _keys.Count > 0 && _keys[0].Expires + PartyEncryption.KeyOverlap <= utcNow )
        {
            var k = _keys[0];
            _keys.RemoveAt( 0 );
            k.Private.Dispose();
            _store.TryTrash( logger, k.Path, immediateDelete: true );
        }
    }

    // Must be called under the lock: the current key is the last one created at or before utcNow. A key created in the
    // future (the clock went backwards) is kept to decrypt what was encrypted for it (deleting a readable key loses
    // the data it encrypts) but it is not the current one before its creation date.
    Key? GetCurrent( DateTime utcNow )
    {
        for( int i = _keys.Count - 1; i >= 0; --i )
        {
            if( _keys[i].Created <= utcNow ) return _keys[i];
        }
        return null;
    }

    // Must be called under the lock.
    bool IsNewKeyDue( DateTime utcNow ) => GetCurrent( utcNow ) is not { } current || current.Expires - PartyEncryption.KeyOverlap <= utcNow;

    /// <summary>
    /// Gets whether the published key must change (see <see cref="GetPublished"/>): there is no key, or the current one
    /// ends in less than <see cref="PartyEncryption.KeyOverlap"/>.
    /// </summary>
    internal bool IsNewKeyDue( DateTime utcNow, PartyEncryptionKey? published )
    {
        lock( _lock )
        {
            return IsNewKeyDue( utcNow ) || published == null || !published.Equals( GetCurrent( utcNow )!.Published );
        }
    }

    /// <summary>
    /// Gets the current public key, signed by the party (a new key is created when the current one ends in less than
    /// <see cref="PartyEncryption.KeyOverlap"/>).
    /// </summary>
    internal PartyEncryptionKey GetPublished( IActivityLineEmitter logger, ILocalKeys signer, DateTime utcNow )
    {
        lock( _lock )
        {
            Prune( logger, utcNow );
            if( IsNewKeyDue( utcNow ) )
            {
                // Sorted by creation: a key created in the future stays after it.
                var created = Create( utcNow );
                int idx = _keys.FindLastIndex( k => k.Created <= utcNow ) + 1;
                _keys.Insert( idx, created );
                logger.Info( $"New encryption key for '{_party}'." );
            }
            var k = GetCurrent( utcNow )!;
            return k.Published ??= new PartyEncryptionKey( k.Spki, signer.Sign( PartyEncryption.KeyPurpose, k.Spki, k.Expires ).Encoded.Span );
        }
    }

    /// <summary>
    /// Finds a private key by its identifier (it can still be used: its end plus <see cref="PartyEncryption.KeyOverlap"/>
    /// is not reached).
    /// </summary>
    internal ECDiffieHellman? Find( ReadOnlySpan<byte> keyId, DateTime utcNow )
    {
        lock( _lock )
        {
            foreach( var k in _keys )
            {
                if( k.Id.AsSpan().SequenceEqual( keyId ) && k.Expires + PartyEncryption.KeyOverlap > utcNow ) return k.Private;
            }
            return null;
        }
    }

    internal void OnTeardown()
    {
        lock( _lock )
        {
            foreach( var k in _keys ) k.Private.Dispose();
            _keys.Clear();
        }
    }
}
