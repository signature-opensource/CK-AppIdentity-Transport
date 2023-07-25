using CK.Core;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace CK.AppIdentity.KeyManagement
{
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
                bool allowClockSet = GetAllowClockSet( monitor, configuration );

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
                    return new RemoteKeys( _localKeys, _remote, new RemoteIdentityKey( c ), autoTrust, allowClockSet );
                }
                monitor.Info( $"No trusted identity found for remote '{_remote}'." );
                return new RemoteKeys( _localKeys, _remote, null, autoTrust, allowClockSet );

                static string ExtractTimeName( string s )
                {
                    return s.Substring( s.IndexOf( '.' ) + 1 );
                }
            }

            static bool GetAllowClockSet( IActivityMonitor monitor, ImmutableConfigurationSection configuration )
            {
                return configuration.LookupBooleanValue( monitor, nameof( AllowClockSet ) );
            }

            AutoTrustKey GetAutoTrustKey( IActivityMonitor monitor, ImmutableConfigurationSection configuration )
            {
                AutoTrustKey autoTrust = AutoTrustKey.Never;
                var a = configuration.TryLookupValue( nameof( AutoTrustKey ) );
                if( a != null && !Enum.TryParse( a, true, out autoTrust ) )
                {
                    monitor.Warn( $"Unable to parse '{configuration.Path}:{nameof( AutoTrustKey )}' value, expected '{AutoTrustKey.Never}', '{AutoTrustKey.Once}' or '{AutoTrustKey.Always}' but got '{a}'. Using default '{AutoTrustKey.Never}'." );
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
}
