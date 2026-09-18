using CK.Core;
using System;

namespace CK.AppIdentity.KeyManagement;

sealed partial class RemoteKeys : IRemoteKeys
{
    internal const string PublicIdentityFilePattern = "Identity.*.public";
    readonly LocalKeys _localKeys;
    readonly IRemoteParty _remote;
    RemoteIdentityKey? _identity;
    readonly TimeSpan _maxClockOffset;
    readonly AutoTrustKey _autoTrustKey;

    // The replay cache belongs here, with the remote it protects: one cache, one lock, one file per
    // remote. It used to be a single shared ring on LocalKeys indexed by remote name, which was a
    // hand-rolled index onto the association this object already is.
    readonly RemoteNonceCache _nonceCache;

    RemoteKeys( LocalKeys localKeys,
                IRemoteParty remote,
                RemoteIdentityKey? identity,
                AutoTrustKey autoTrustKey,
                TimeSpan maxClockOffset,
                RemoteNonceCache nonceCache )
    {
        _localKeys = localKeys;
        _remote = remote;
        _identity = identity;
        _autoTrustKey = autoTrustKey;
        _maxClockOffset = maxClockOffset;
        _nonceCache = nonceCache;
        remote.ApplicationIdentityService.Heartbeat.Sync += OnHeartbeat;
    }

    void OnHeartbeat( IActivityMonitor monitor, int callCount )
    {
        // Prune first: an idle process must not hold nonces that can no longer be replayed.
        _nonceCache.Prune( _remote.ApplicationIdentityService.SystemClock.UtcNow, _maxClockOffset );
        _nonceCache.Save( monitor );
    }

    /// <summary>
    /// Called when this remote's keys are unplugged.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="destroyed">
    /// True when the remote party itself is gone, as opposed to the application shutting down. Its
    /// replay record then has no meaning any more, and leaving it behind would resurrect on a party
    /// that later takes the same name.
    /// </param>
    internal void OnTeardown( IActivityMonitor monitor, bool destroyed )
    {
        _remote.ApplicationIdentityService.Heartbeat.Sync -= OnHeartbeat;
        _identity?.OnTeardown();
        if( destroyed ) _nonceCache.Delete( monitor );
        else _nonceCache.Save( monitor );
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

    public bool ApplyReadTrustInfo( IActivityLineEmitter logger, in ReadTrustInfo trustInfo )
    {
        Throw.CheckArgument( trustInfo.CurrentKey == null || trustInfo.CurrentKey.Equals( trustInfo.CurrentKeyData ) );
        Throw.CheckArgument( !trustInfo.FoundTrustedKey || TrustedIdentity != null );
        if( trustInfo.FoundTrustedKey )
        {
            // We trust the remote (we can update our trusted identity key).
            if( !TrustedIdentity!.Equals( trustInfo.CurrentKeyData ) )
            {
                logger.Info( $"Updating the remote '{Party}' trusted key that has changed." );
                SetTrustedIdentity( logger, trustInfo.CurrentKey ?? new RemoteIdentityKey( trustInfo.CurrentKeyData ) );
                return true;
            }
        }
        else
        {
            // We don't trust the remote. Depending on AutoTrustKey we may...
            if( TrustedIdentity == null )
            {
                if( AutoTrustKey != AutoTrustKey.Never )
                {
                    logger.Warn( $"Initializing the remote '{Party}' trusted key because its '{nameof( AutoTrustKey )}' is {AutoTrustKey}." );
                    SetTrustedIdentity( logger, trustInfo.CurrentKey ?? new RemoteIdentityKey( trustInfo.CurrentKeyData ) );
                    return true;
                }
            }
            else
            {
                if( AutoTrustKey == AutoTrustKey.Always )
                {
                    logger.Warn( $"Updating the remote '{Party}' trusted key because its '{nameof( AutoTrustKey )}' is {AutoTrustKey}." );
                    SetTrustedIdentity( logger, trustInfo.CurrentKey ?? new RemoteIdentityKey( trustInfo.CurrentKeyData ) );
                    return true;
                }
            }
        }
        return false;
    }

    public bool CheckClockOffset( IActivityLineEmitter logger, TimeSpan clockOffset, LogLevel logLevel = LogLevel.Error )
    {
        if( clockOffset > _maxClockOffset || clockOffset < -_maxClockOffset )
        {
            if( logLevel != LogLevel.None ) logger.Log( logLevel, $"Invalid nonce creation time '{clockOffset}' for '{_remote}'. It must be less than '{_maxClockOffset}'." );
            return false;
        }
        return true;
    }

    public bool CheckAndAddNonceValue( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error )
    {
        // Partitioned by remote and checked-and-added in one operation: two concurrent connections
        // replaying the same nonce must not both pass.
        bool ok = _nonceCache.CheckAndAdd( nonce.Nonce,
                                           nonce.CreationTime,
                                           _remote.ApplicationIdentityService.SystemClock.UtcNow,
                                           _maxClockOffset,
                                           out bool evicted );
        if( evicted )
        {
            // Only a peer handshaking far faster than any legitimate one reaches this, and the
            // degradation is confined to that peer. Worth saying out loud: its replay window is
            // now shorter than configured.
            logger.Log( LogLevel.Warn, ActivityMonitor.Tags.ToBeInvestigated,
                        $"Nonce cache for '{_remote}' is full ({IRemoteKeys.MaxNonceCacheEntries} entries within " +
                        $"{_maxClockOffset}): dropping still-valid entries. This remote is handshaking abnormally fast." );
        }
        if( !ok && logLevel != LogLevel.None )
        {
            logger.Log( logLevel, ActivityMonitor.Tags.ToBeInvestigated,
                        $"Nonce value '{nonce.Nonce:X}' has already been used for '{_remote}'." );
        }
        return ok;
    }

    public bool CheckNonce( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error )
    {
        return nonce.CheckCreationTimeKind( logger, Party.FullName, logLevel )
               && CheckClockOffset( logger, nonce.CreationTime - _remote.ApplicationIdentityService.SystemClock.UtcNow )
               && CheckAndAddNonceValue( logger, nonce, logLevel );
    }
}
