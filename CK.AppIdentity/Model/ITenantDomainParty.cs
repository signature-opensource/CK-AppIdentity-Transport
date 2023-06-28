using Microsoft.Extensions.Configuration;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity
{
    /// <summary>
    /// A tenant domain party is both a <see cref="IOwnedParty"/> (owned by the root <see cref="IApplicationIdentityService"/>)
    /// and a local party.
    /// </summary>
    public interface ITenantDomainParty : IOwnedParty, ILocalParty
    {
        /// <summary>
        /// Gets the <see cref="TenantDomainPartyConfiguration"/> configuration.
        /// </summary>
        new TenantDomainPartyConfiguration Configuration { get; }

        /// <summary>
        /// Gets the owner that is the root <see cref="IApplicationIdentityService"/>.
        /// </summary>
        new IApplicationIdentityService Owner { get; }

    }
}
