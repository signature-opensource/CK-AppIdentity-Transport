using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CK.AppIdentity
{
    /// <summary>
    /// Base class for <see cref="ApplicationIdentityService"/> and <see cref="DomainApplicationIdentity"/>.
    /// </summary>
    public abstract class ApplicationIdentityBase
    {
        readonly LocalParty _local;
        readonly ApplicationIdentityConfiguration _configuration;
        internal RemoteParty[] _remotes;

        private protected ApplicationIdentityBase( ApplicationIdentityConfiguration configuration )
        {
            _local = new LocalParty( (IApplicationIdentity)this, configuration.Local );
            _configuration = configuration;
            _remotes = configuration.Remotes.Select( c => new RemoteParty( (IApplicationIdentity)this, c ) ).ToArray();
        }

        /// <inheritdoc cref="IApplicationIdentity.Local" />
        public ILocalParty Local => _local;

        /// <inheritdoc cref="IApplicationIdentity.Remotes" />
        public IReadOnlyCollection<IRemoteParty> Remotes => _remotes;

        /// <inheritdoc cref="IApplicationIdentity.Configuration" />
        public ApplicationIdentityConfiguration Configuration => _configuration;

    }
}
