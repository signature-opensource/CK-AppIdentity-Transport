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

                RemoteIdentityKeyData? c = null;
                foreach( var f in FilterFileNames( monitor,
                                                   DateTime.UtcNow,
                                                   Directory.EnumerateFiles( _store.FolderPath, PublicIdentityFilePattern ),
                                                   ExctractTimeName ) )
                {
                    if( c == null || f.TimeName > c.TimeName )
                    {
                        var better = TryLoad( monitor, f.TimeName, f.Path );
                        if( better != null ) c = better;
                    }
                    else
                    {
                        LogAndCleanup( monitor, f.Path, $"Obsolete public identity found ('{c.TimeName}' is more recent)." );
                    }
                }
                if( c != null )
                {
                    monitor.Info( $"Found trusted identity key '{c.TimeName}' for remote '{_remote}'." );
                    return new RemoteKeys( _remote, new RemoteIdentityKey( c ) );
                }
                monitor.Info( $"No trusted identity found for remote '{_remote}'." );
                return new RemoteKeys( _remote, null );

                static string ExctractTimeName( string s )
                {
                    int start = s.IndexOf( '.' ) + 1;
                    return s.Substring( start, s.LastIndexOf( '.' ) - start );
                }

            }

            RemoteIdentityKeyData? TryLoad( IActivityMonitor monitor, DateTime timeName, string path )
            {
                try
                {
                    return new RemoteIdentityKeyData( timeName, PublicKey.CreateFromSubjectPublicKeyInfo( File.ReadAllBytes( path ), out _ ) );
                }
                catch ( Exception ex )
                {
                    monitor.Error( $"While loading '{path}'.", ex );
                    return null;
                }
            }
        }


    }
}
