using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.IO;
using System.Security.Principal;
using System.Threading;

namespace CK.AppIdentity.KeyManagement
{
    sealed partial class RemoteKeys : IRemoteKeys
    {
        internal const string PublicIdentityFilePattern = "Identity.*.public";

        readonly IRemoteParty _remote;
        RemoteIdentityKey? _identity;

        RemoteKeys( IRemoteParty remote, RemoteIdentityKey? identity )
        {
            _remote = remote;
            _identity = identity;
        }

        public IRemoteParty Party => _remote;

        public RemoteIdentityKey? TrustedIdentity => _identity;

        public bool SetTrustedIdentity( IActivityMonitor monitor, RemoteIdentityKey? identity )
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
                    monitor.Info( $"Removing trusted identity '{current.Name}' for remote '{_remote}'. This remote has no more trusted identity." );
                }
                else
                {
                    monitor.Info( $"Removing trusted identity '{current.Name}' for remote '{_remote}', replaced by '{identity.Name}'." );
                }
                var cPath = _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{current.Name}.public" );
                _remote.SharedFileStore.TryTrash( monitor, cPath );
            }
            _identity = identity;
            if( identity != null )
            {
                var cPath = _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{identity.Name}.public" );
                identity.WriteFile( cPath );
            }
            return true;
        }

    }
}
