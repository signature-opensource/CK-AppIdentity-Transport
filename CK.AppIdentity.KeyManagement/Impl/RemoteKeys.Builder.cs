using CK.Core;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace CK.AppIdentity.KeyManagement
{
    sealed partial class RemoteKeys
    {
        internal sealed class Builder : KeyLoader
        {
            readonly IRemoteParty _remote;

            public Builder( IRemoteParty remote )
                : base( remote.SharedFileStore )
            {
                _remote = remote;
            }

            internal RemoteKeys Build( IActivityMonitor monitor )
            {
                DateTime now = DateTime.UtcNow;

                AutoTrustKey autoTrust = AutoTrustKey.Never;
                var a = _remote.Configuration.Configuration.TryLookupValue( nameof( AutoTrustKey ) );
                if( a != null && !Enum.TryParse( a, true, out autoTrust ) )
                {
                    monitor.Warn( $"Unable to parse {nameof( AutoTrustKey )} value, expected '{AutoTrustKey.Never}', '{AutoTrustKey.Once}' or '{AutoTrustKey.Always}' but got '{a}'. Using default '{AutoTrustKey.Never}'." );
                }

                RemoteIdentityKeyData? c = null;
                foreach( var f in FilterFileNames( monitor,
                                                   DateTime.UtcNow,
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
                    return new RemoteKeys( _remote, new RemoteIdentityKey( c ), autoTrust );
                }
                monitor.Info( $"No trusted identity found for remote '{_remote}'." );
                return new RemoteKeys( _remote, null, autoTrust );

                static string ExtractTimeName( string s )
                {
                    return s.Substring( s.IndexOf( '.' ) + 1 );
                }
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
