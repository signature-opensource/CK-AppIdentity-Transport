using CK.Core;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity
{
    public sealed class V2LocalParty : V2AppIdentityObject, V2IParty
    {
        readonly V2AppIdentityDomain _domain;
        internal bool _isDestroyed;

        internal V2LocalParty( V2LocalPartyConfiguration configuration, V2AppIdentityDomain domain )
            : base( configuration )
        {
            _domain = domain;
        }

        /// <summary>
        /// Gets the configuration object.
        /// </summary>
        public V2LocalPartyConfiguration Configuration => Unsafe.As<V2LocalPartyConfiguration>( _configuration );

        /// <summary>
        /// Gets this party name. This is "$Local" for the <see cref="V2ApplicationIdentityService"/>
        /// and the "domain controller name" for <see cref="V2RemoteDomain"/>.
        /// </summary>
        public string PartyName => Configuration.PartyName;

        public V2AppIdentityDomain Domain => _domain;

        public bool IsRooted => _domain is V2ApplicationIdentityService;

        public bool IsDestroyed => _isDestroyed;
    }
}
