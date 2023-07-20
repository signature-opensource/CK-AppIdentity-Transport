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
        readonly LocalKeys _localKeys;
        readonly IRemoteParty _remote;
        RemoteIdentityKey? _identity;
        readonly AutoTrustKey _autoTrustKey;
        readonly bool _allowClockSet;

        RemoteKeys( LocalKeys localKeys, IRemoteParty remote, RemoteIdentityKey? identity, AutoTrustKey autoTrustKey, bool allowClockSet )
        {
            _localKeys = localKeys;
            _remote = remote;
            _identity = identity;
            _autoTrustKey = autoTrustKey;
            _allowClockSet = allowClockSet;
        }

        public ILocalKeys LocalKeys => _localKeys;

        public IRemoteParty Party => _remote;

        public RemoteIdentityKey? TrustedIdentity => _identity;

        public AutoTrustKey AutoTrustKey => _autoTrustKey;

        public bool AllowClockSet => _allowClockSet;

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

        public bool CheckNonceCache( IActivityLineEmitter logger, DateTime utcNow, ulong nonce, bool addNonce )
        {
            if( _localKeys.NonceCache.Find( nonce ) ) return false;
            if( addNonce ) _localKeys.NonceCache.Add( nonce );
            return true;
        }

        public void AddNonce( IActivityLineEmitter logger, DateTime utcNow, ulong nonce )
        {
            _localKeys.NonceCache.Add( nonce );
        }
    }
}
