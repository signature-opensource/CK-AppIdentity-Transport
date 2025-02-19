using CK.Core;
using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement;

sealed partial class RemoteKeys
{
    internal sealed class Builder : KeyLoader
    {
        readonly LocalKeys _localKeys;
        readonly IRemoteParty _remote;

        public Builder( LocalKeys localKeys, IRemoteParty remote )
            : base( remote.SharedFileStore )
        {
            _localKeys = localKeys;
            _remote = remote;
        }

        internal RemoteKeys Build( IActivityMonitor monitor )
        {
            ImmutableConfigurationSection configuration = _remote.Configuration.Configuration;
            AutoTrustKey autoTrust = GetAutoTrustKey( monitor, configuration );
            TimeSpan maxClockOffset = GetMaxClockOffset( monitor, configuration );
            DateTime now = _remote.ApplicationIdentityService.SystemClock.UtcNow;
            RemoteIdentityKeyData? c = null;
            foreach( var f in FilterFileNames( monitor,
                                               now,
                                               Directory.EnumerateFiles( _store.FolderPath, PublicIdentityFilePattern ),
                                               ExtractTimeName ) )
            {
                if( c == null || f.TimeName > c.TimeName )
                {
                    var better = TryLoad( monitor, f.TimeName, f.Path );
                    if( better != null ) c = better;
                }
                else
                {
                    LogAndCleanup( monitor, f.Path, $"Obsolete public identity found ('{c.Name}' is more recent)." );
                }
            }
            if( c != null )
            {
                monitor.Info( $"Found trusted identity key '{c.Name}' for remote '{_remote}'." );
                return new RemoteKeys( _localKeys, _remote, new RemoteIdentityKey( c ), autoTrust, maxClockOffset );
            }
            monitor.Info( $"No trusted identity found for remote '{_remote}'." );
            return new RemoteKeys( _localKeys, _remote, null, autoTrust, maxClockOffset );

            static string ExtractTimeName( string s )
            {
                return s.Substring( s.IndexOf( '.' ) + 1 );
            }
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
            if( a != null && !Enum.TryParse( a, true, out autoTrust ) )
            {
                monitor.Warn( $"Unable to parse '{configuration.Path}:{nameof( AutoTrustKey )}' value, " +
                              $"expected '{AutoTrustKey.Never}', '{AutoTrustKey.Once}' or '{AutoTrustKey.Always}' but got '{a}'. " +
                              $"Using default '{AutoTrustKey.Never}'." );
            }
            if( autoTrust != AutoTrustKey.Never )
            {
                monitor.Info( $"Remote '{_remote}' uses {nameof( AutoTrustKey )}: \"{autoTrust}\"." );
            }
            return autoTrust;
        }

        RemoteIdentityKeyData? TryLoad( IActivityMonitor monitor, DateTime timeName, in NormalizedPath path )
        {
            try
            {
                return new RemoteIdentityKeyData( timeName, PublicKey.CreateFromSubjectPublicKeyInfo( File.ReadAllBytes( path ), out _ ) );
            }
            catch ( Exception ex )
            {
                LogAndCleanup( monitor, path, $"While loading '{path}'", LogLevel.Error, ex );
                return null;
            }
        }
    }


}
