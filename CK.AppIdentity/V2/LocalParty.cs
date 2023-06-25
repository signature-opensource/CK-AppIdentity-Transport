using CK.Core;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity
{
    public sealed class LocalParty : ApplicationIdentityObject, IParty
    {
        readonly ApplicationIdentityDomain _domain;
        internal bool _isDestroyed;

        internal LocalParty( LocalPartyConfiguration configuration, ApplicationIdentityDomain domain )
            : base( configuration )
        {
            _domain = domain;
        }

        /// <summary>
        /// Gets the configuration object.
        /// </summary>
        public LocalPartyConfiguration Configuration => Unsafe.As<LocalPartyConfiguration>( _configuration );

        /// <summary>
        /// Gets this party name. This is "$Local" for the <see cref="ApplicationIdentityService"/>
        /// and the "domain controller name" for <see cref="RemoteDomain"/>.
        /// </summary>
        public string PartyName => Configuration.PartyName;

        public ApplicationIdentityDomain Domain => _domain;

        public bool IsRooted => _domain is ApplicationIdentityService;

        public bool IsDestroyed => _isDestroyed;
    }
}
