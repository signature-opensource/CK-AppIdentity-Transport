using CK.Core;
using System;

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
                throw new NotImplementedException();
            }
        }


    }
}
