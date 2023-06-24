using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity
{

    /// <summary>
    /// A Remote with Remotes is a domain.
    /// </summary>
    public class V2AppIdentityDomain : V2AppIdentityObject
    {
        readonly V2LocalParty _local;
        readonly V2IRemote[] _remotes;
        readonly V2ApplicationIdentityService _appIdentityService;

        internal V2AppIdentityDomain( V2DomainConfiguration configuration, V2ApplicationIdentityService? appIdentityService )
            : base( configuration )
        {
            _local = new V2LocalParty( configuration.Local, this );
            _appIdentityService = appIdentityService ?? (V2ApplicationIdentityService)this;
            _remotes = configuration.Remotes.Select( c =>
                c switch
                {
                    V2RemotePartyConfiguration p => new V2RemoteParty( p, this ),
                    V2DomainConfiguration d => new V2RemoteDomain( d, this ),
                    _ => Throw.NotSupportedException<V2IRemote>()
                } ).ToArray();
        }

        /// <summary>
        /// Gets the root application identity.
        /// This is this object if this is the root identity service.
        /// </summary>
        public V2ApplicationIdentityService ApplicationIdentityService => _appIdentityService;

        /// <summary>
        /// Gets the configuration object.
        /// </summary>
        public V2DomainConfiguration Configuration => Unsafe.As<V2DomainConfiguration>( _configuration );

        /// <summary>
        /// Gets the local party. Its <see cref="V2LocalPartyConfiguration.PartyName"/> is the
        /// domain leaf name.
        /// </summary>
        public V2LocalParty Local => _local;

        /// <summary>
        /// Gets the remotes: <see cref="V2RemoteDomain"/> or <see cref="V2RemoteParty"/> <see cref="V2DomainBase"/>.
        /// </summary>
        public IReadOnlyCollection<V2IRemote> Remotes => _remotes;

    }
}
