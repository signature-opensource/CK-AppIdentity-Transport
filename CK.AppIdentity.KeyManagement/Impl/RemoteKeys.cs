using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Security.Principal;

namespace CK.AppIdentity.KeyManagement
{
    sealed partial class RemoteKeys : IRemoteKeys
    {
        readonly IRemoteParty _remote;
        readonly RemoteIdentityKey? _identity;

        RemoteKeys( IRemoteParty remote, RemoteIdentityKey identity )
        {
            _remote = remote;
            _identity = identity;
        }

        public IRemoteParty Party => _remote;

        public RemoteIdentityKey? TrustedIdentity => _identity;
    }
}
