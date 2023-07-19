using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using static CK.Core.CheckedWriteStream;

namespace CK.AppIdentity.KeyManagement
{
    sealed partial class RemoteKeys : IRemoteKeys
    {
        internal const string PublicIdentityFilePattern = "Identity.*.public";
        const int NonceCacheCount = 1024;

        readonly IRemoteParty _remote;
        RemoteIdentityKey? _identity;
        AutoTrustKey _autoTrustKey;

        RemoteKeys( IRemoteParty remote, RemoteIdentityKey? identity, AutoTrustKey autoTrustKey )
        {
            _remote = remote;
            _identity = identity;
            _autoTrustKey = autoTrustKey;
        }

        public IRemoteParty Party => _remote;

        public RemoteIdentityKey? TrustedIdentity => _identity;

        public AutoTrustKey AutoTrustKey => _autoTrustKey;

        public bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKey? identity )
        {
            var current = _identity;
            if( (current == null && identity == null)
                || (current != null && current.Equals( identity )) )
            {
                return false;    
            }
            if( current != null )
            {
                if( identity == null )
                {
                    logger.Info( $"Removing trusted identity '{current.Name}' for remote '{_remote}'. This remote has no more trusted identity." );
                }
                else
                {
                    logger.Info( $"Removing trusted identity '{current.Name}' for remote '{_remote}', replaced by '{identity.Name}'." );
                }
                var cPath = _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{current.Name}.public" );
                _remote.SharedFileStore.TryTrash( logger, cPath );
            }
            _identity = identity;
            if( identity != null )
            {
                var cPath = _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{identity.Name}.public" );
                identity.WriteFile( cPath );
            }
            return true;
        }

        public bool CheckAndUpdateNonceCache( IActivityLineEmitter logger, ulong nonce, bool addNonce )
        {
            var noncePath = _remote.SharedFileStore.FolderPath.AppendPart( "Nonce.cache" );
            //var buffer = ArrayPool<byte>.Shared.Rent( 8192 );
            //var ulongs = MemoryMarshal.Cast<byte, ulong>( buffer );
            //try
            //{
            //    using var hFile = File.OpenHandle( noncePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, FileOptions.None, 8192 );
            //    var len = RandomAccess.Read( hFile, buffer, 0 );
            //    if( len == 0 )
            //    {
            //        logger.Trace( $"Creating '{noncePath}' file." );
            //        ulongs[0] = 0;
            //        ulongs[1] = nonce;
            //    }
            //}
            //finally
            //{
            //    ArrayPool<byte>.Shared.Return( buffer );
            //}
            return true;
        }

    }
}
