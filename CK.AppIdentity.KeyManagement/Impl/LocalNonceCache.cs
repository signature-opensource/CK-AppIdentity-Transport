using CK.Core;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// Very basic cache of 1023 last nonces in a 8KiB array.
    /// This cache is small because the time window during which checks are done is small
    /// and only trusted remotes initial requests nonce are added.
    /// <para>
    /// The nonces are saved on <see cref="IApplicationIdentityService.Heartbeat"/> and
    /// when the local is torn down.
    /// </para>
    /// <para>
    /// We may use a Bloom filter here (but this would require a lookup in the file on hash collision).
    /// </para>
    /// </summary>
    sealed class LocalNonceCache
    {
        const int CacheSize = 1023;
        readonly ulong[] _nonces;
        uint _head;
        readonly NormalizedPath _filePath;
        uint _version;
        uint _savedVersion;

        LocalNonceCache( NormalizedPath filePath, ulong[] nonces, uint head )
        {
            _filePath = filePath;
            _nonces = nonces;
            _head = head;
        }

        public bool Find( ulong key ) => _nonces.AsSpan().Contains( key );

        public void Add( ulong nonce )
        {
            lock( _nonces )
            {
                if( ++_head > CacheSize ) _head = 0;
                _nonces[_head] = nonce;
                ++_version;
            }
        }

        /// <summary>
        /// Called from the ApplicationIdentity's loop by the heartbeat or by
        /// the local keys OnTearDown. This saves only if at least one nonce has
        /// been added since the last save.
        /// </summary>
        /// <param name="monitor">The ApplicationIdentity's agent monitor.</param>
        /// <returns>True on success, false if an error occured.</returns>
        public bool Save( IActivityMonitor monitor )
        {
            if( _savedVersion == _version ) return true;
            try
            {
                using var hFile = File.OpenHandle( _filePath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None, FileOptions.None );
                lock( _nonces )
                {
                    _savedVersion = _version;
                    _nonces[CacheSize] = _head;
                    RandomAccess.Write( hFile, MemoryMarshal.Cast<ulong, byte>( _nonces ), 0 );
                }
                return true;
            }
            catch( Exception ex )
            {
                monitor.Error( $"While saving '{_filePath}'.", ex );
                return false;
            }
        }

        public static LocalNonceCache Create( IActivityMonitor monitor, NormalizedPath filePath )
        {
            var nonces = new ulong[CacheSize + 1];
            using var hFile = File.OpenHandle( filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, FileOptions.None );
            var len = RandomAccess.Read( hFile, MemoryMarshal.Cast<ulong, byte>( nonces ), 0 ) / 8;
            uint head;
            if( len == 0 )
            {
                monitor.Trace( $"Creating '{filePath}' file." );
                head = 0;
            }
            else head = (uint)nonces[CacheSize];
            return new LocalNonceCache( filePath, nonces, head );
        }
    }
}
