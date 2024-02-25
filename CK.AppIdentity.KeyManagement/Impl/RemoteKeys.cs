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
        readonly TimeSpan _maxClockOffset;
        readonly AutoTrustKey _autoTrustKey;

        RemoteKeys( LocalKeys localKeys, IRemoteParty remote, RemoteIdentityKey? identity, AutoTrustKey autoTrustKey, TimeSpan maxClockOffset )
        {
            _localKeys = localKeys;
            _remote = remote;
            _identity = identity;
            _autoTrustKey = autoTrustKey;
            _maxClockOffset = maxClockOffset;
        }

        public ILocalKeys LocalKeys => _localKeys;

        public IRemoteParty Party => _remote;

        public RemoteIdentityKey? TrustedIdentity => _identity;

        public AutoTrustKey AutoTrustKey => _autoTrustKey;

        public TimeSpan MaxClockOffset => _maxClockOffset;

        public bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKeyData? identity )
        {
            if( !SaveDifferingKey( logger, identity ) ) return false;
            _identity = identity != null ? new RemoteIdentityKey( identity ) : null;
            return true;
        }

        public bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKey? identity )
        {
            if( !SaveDifferingKey( logger, identity ) ) return false;
            _identity = identity;
            return true;
        }

        bool SaveDifferingKey( IActivityLineEmitter logger, IPublicKeyData? identity )
        {
            RemoteIdentityKey? current = _identity;
            if( (current == null && identity == null)
                || (current != null && current.Equals( identity )) )
            {
                return false;
            }
            if( identity != null )
            {
                var cPath = _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{identity.Name}.public" );
                identity.WritePublicKeyFile( cPath );
                if( current == null )
                {
                    logger.Info( $"Saving new trusted identity '{identity.Name}' for remote '{_remote}'." );
                }
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
            return true;
        }

        public bool CheckNonce( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error )
        {
            return nonce.CheckCreationTimeKind( logger, Party.FullName, logLevel )
                   && CheckNonce( logger, nonce, out _, out _, logLevel );
        }

        public bool CheckNonce( IActivityLineEmitter logger, in TimedNonce nonce, out TimeSpan clockOffset, out bool validClockOffset, LogLevel logLevel = LogLevel.Error )
        {
            Throw.CheckNotNullArgument( logger );
            Throw.CheckArgument( nonce.CreationTime.Kind == DateTimeKind.Utc );
            validClockOffset = false;
            clockOffset = nonce.CreationTime - _remote.ApplicationIdentityService.SystemClock.UtcNow;
            if( clockOffset > _maxClockOffset || clockOffset < -_maxClockOffset )
            {
                if( logLevel != LogLevel.None ) logger.Log( logLevel, $"Invalid nonce creation time '{clockOffset}' for '{_remote}'. It must be less than '{_maxClockOffset}'." );
                return false;
            }
            validClockOffset = true;
            if( _localKeys.NonceCache.Find( nonce.Nonce ) )
            {
                if( logLevel != LogLevel.None ) logger.Log( logLevel, ActivityMonitor.Tags.ToBeInvestigated, $"Nonce value '{nonce.Nonce:X}' has already been used for '{_remote}'." );
                return false;
            }
            _localKeys.NonceCache.Add( nonce.Nonce );
            return true;
        }

        public bool CheckNonceValue( ulong nonceValue )
        {
            if( _localKeys.NonceCache.Find( nonceValue ) ) return false;
            _localKeys.NonceCache.Add( nonceValue );
            return true;
        }

        public void AddNonceValue( ulong nonce )
        {
            _localKeys.NonceCache.Add( nonce );
        }
    }
}
