using CK.Core;
using System;

namespace CK.AppIdentity.KeyManagement
{
    sealed partial class RemoteKeys : IRemoteKeys
    {
        internal const string PublicIdentityFilePattern = "Identity.*.public";
        readonly LocalKeys _localKeys;
        readonly IRemoteParty _remote;
        RemoteIdentityKey? _identity;
        readonly AutoTrustKey _autoTrustKey;

        RemoteKeys( LocalKeys localKeys, IRemoteParty remote, RemoteIdentityKey? identity, AutoTrustKey autoTrustKey )
        {
            _localKeys = localKeys;
            _remote = remote;
            _identity = identity;
            _autoTrustKey = autoTrustKey;
        }

        public ILocalKeys LocalKeys => _localKeys;

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
                identity.WritePublicKeyFile( cPath );
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
