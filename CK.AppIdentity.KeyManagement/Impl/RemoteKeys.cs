using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Diagnostics;
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
        AutoTrustKey _autoTrustKey;

        RemoteKeys( IRemoteParty remote, RemoteIdentityKey? identity, AutoTrustKey autoTrustKey )
        {
            _remote = remote;
            _identity = identity;
            _autoTrustKey = autoTrustKey;
        }

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
                identity.WriteFile( cPath );
            }
            return true;
        }

    }
}
