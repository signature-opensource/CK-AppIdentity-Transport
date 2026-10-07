using CK.Core;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace CK.AppIdentity.KeyManagement;

sealed partial class RemoteKeys
{
    internal sealed class Builder
    {
        readonly LocalKeys _localKeys;
        readonly IRemoteParty _remote;
        readonly IFileStore _store;

        public Builder( LocalKeys localKeys, IRemoteParty remote )
        {
            _localKeys = localKeys;
            _remote = remote;
            _store = remote.SharedFileStore;
        }

        internal RemoteKeys Build( IActivityMonitor monitor )
        {
            ImmutableConfigurationSection configuration = _remote.Configuration.Configuration;
            AutoTrustKey autoTrust = GetAutoTrustKey( monitor, configuration );
            TimeSpan maxClockOffset = GetMaxClockOffset( monitor, configuration );
            // This local party's record of nonces seen from this remote, kept in the remote's folder.
            var nonceCache = RemoteNonceCache.Load( monitor, _remote, _localKeys.Party );
            var pinned = LoadPin( monitor );
            if( pinned != null )
            {
                monitor.Info( $"Found pinned identity #{pinned.Seq} for remote '{_remote}'{(pinned.IsAbandonment ? " (decommissioned)" : "")}." );
            }
            else
            {
                monitor.Info( $"No trusted identity found for remote '{_remote}'." );
            }
            var history = LoadHistory( monitor, pinned );
            var keys = new RemoteKeys( _localKeys, _remote, pinned, history, autoTrust, maxClockOffset, nonceCache );
            if( pinned != null )
            {
                lock( keys._trustLock ) keys.PruneHistory( monitor );
            }
            return keys;
        }

        /// <summary>
        /// Loads the most recent pin. Two processes sharing this folder may each have written theirs:
        /// the highest sequence wins and the others go to the '$TrashBin', like any file this loader
        /// does not keep.
        /// </summary>
        KeyEvent? LoadPin( IActivityMonitor monitor )
        {
            var folder = _store.FolderPath;
            if( !Directory.Exists( folder ) ) return null;
            // No migration (DESIGN-key-pre-rotation Q1): a bare public key cannot be linked to a log.
            foreach( var f in Directory.EnumerateFiles( folder, LegacyPublicFilePattern ) )
            {
                monitor.Info( $"Trashing '{f}': a trusted identity is now a key event ('{TrustFilePattern}')." );
                _store.TryTrash( monitor, f );
            }
            KeyEvent? best = null;
            NormalizedPath bestPath = default;
            foreach( var f in Directory.EnumerateFiles( folder, TrustFilePattern ) )
            {
                NormalizedPath path = f;
                var name = Path.GetFileNameWithoutExtension( path.LastPart );
                KeyEvent? e = null;
                try
                {
                    int seq = -1;
                    Throw.CheckData( "The file name must be 'Identity.{Seq}.trust'.",
                                     name.StartsWith( "Identity.", StringComparison.Ordinal )
                                     && int.TryParse( name.AsSpan( 9 ), NumberStyles.None, CultureInfo.InvariantCulture, out seq ) );
                    e = KeyEvent.Read( _store.ReadAllBytes( path ) );
                    Throw.CheckData( "The file name must be the sequence of the event it holds.", e.Seq == seq );
                    Throw.CheckData( "The event must be signed by the key it reveals, for this remote.", e.VerifySignature( _remote.FullName ) );
                }
                catch( Exception ex )
                {
                    monitor.Error( $"Invalid trusted identity file '{path}'. Sending it to the '$TrashBin'.", ex );
                    _store.TryTrash( monitor, path );
                    continue;
                }
                if( best == null || e.Seq > best.Seq )
                {
                    if( best != null ) Obsolete( monitor, bestPath );
                    best = e;
                    bestPath = path;
                }
                else
                {
                    Obsolete( monitor, path );
                }
            }
            return best;

            void Obsolete( IActivityMonitor monitor, NormalizedPath path )
            {
                monitor.Info( $"Trashing obsolete trusted identity '{path}'." );
                _store.TryTrash( monitor, path );
            }
        }

        /// <summary>
        /// Loads the events the pin moved past: walking back from the pin, each one must link to the
        /// next. The first gap or broken link ends the history; whatever else is there is removed.
        /// </summary>
        List<KeyEvent> LoadHistory( IActivityMonitor monitor, KeyEvent? pinned )
        {
            var history = new List<KeyEvent>();
            var folder = _store.FolderPath.AppendPart( HistoryFolderName );
            if( !Directory.Exists( folder ) ) return history;
            var files = new Dictionary<int, NormalizedPath>();
            foreach( var f in Directory.EnumerateFiles( folder ) )
            {
                NormalizedPath path = f;
                if( path.LastPart.EndsWith( ".event", StringComparison.Ordinal )
                    && int.TryParse( path.LastPart.AsSpan( 0, path.LastPart.Length - 6 ), NumberStyles.None, CultureInfo.InvariantCulture, out var seq ) )
                {
                    files[seq] = path;
                }
                else
                {
                    _store.TryTrash( monitor, path, immediateDelete: true );
                }
            }
            var expected = pinned;
            while( expected != null && files.Remove( expected.Seq - 1, out var path ) )
            {
                KeyEvent? e = null;
                try
                {
                    e = KeyEvent.Read( _store.ReadAllBytes( path ) );
                }
                catch( Exception ex )
                {
                    monitor.Warn( $"Invalid key history file '{path}'.", ex );
                }
                if( e == null || e.Seq != expected.Seq - 1 || !KeyEventChain.Links( _remote.FullName, e, expected ) )
                {
                    _store.TryTrash( monitor, path, immediateDelete: true );
                    break;
                }
                history.Insert( 0, e );
                expected = e;
            }
            foreach( var path in files.Values )
            {
                monitor.Info( $"Removing '{path}': not part of the history of the pinned identity." );
                _store.TryTrash( monitor, path, immediateDelete: true );
            }
            return history;
        }

        static TimeSpan GetMaxClockOffset( IActivityMonitor monitor, ImmutableConfigurationSection configuration )
        {
            var maxClockOffset = IRemoteKeys.DefaultMaxClockOffset;
            var o = configuration.TryLookupValue( nameof( MaxClockOffset ) );
            if( o != null )
            {
                if( TimeSpan.TryParse( o, CultureInfo.InvariantCulture, out var offset )
                    && offset >= TimeSpan.FromMinutes( 1 )
                    && offset <= TimeSpan.FromMinutes( 20 ) )
                {
                    maxClockOffset = offset;
                }
                else
                {
                    monitor.Warn( $"Unable to parse '{configuration.Path}:{nameof( MaxClockOffset )}' value, " +
                                  $"expected time span between '00:01:00' (1 minute) and '00:20:00' (20 minutes) but got '{o}'. " +
                                  $"Using default '{IRemoteKeys.DefaultMaxClockOffset}'." );
                }
            }
            return maxClockOffset;
        }

        AutoTrustKey GetAutoTrustKey( IActivityMonitor monitor, ImmutableConfigurationSection configuration )
        {
            AutoTrustKey autoTrust = AutoTrustKey.Never;
            var a = configuration.TryLookupValue( nameof( AutoTrustKey ) );
            // Enum.TryParse also accepts numerals and any combination of them, so "1" parses as Once
            // and "7" as an undefined value that passes every "!= Never" test. IsDefined rejects both:
            // this is a security switch, a typo in it must not silently grant trust.
            if( a != null && !(Enum.TryParse( a, true, out autoTrust ) && Enum.IsDefined( autoTrust )) )
            {
                monitor.Warn( $"Unable to parse '{configuration.Path}:{nameof( AutoTrustKey )}' value, " +
                              $"expected '{AutoTrustKey.Never}' or '{AutoTrustKey.Once}' but got '{a}'. " +
                              $"Using default '{AutoTrustKey.Never}'." );
            }
            if( autoTrust != AutoTrustKey.Never )
            {
                monitor.Info( $"Remote '{_remote}' uses {nameof( AutoTrustKey )}: \"{autoTrust}\"." );
            }
            return autoTrust;
        }
    }
}
