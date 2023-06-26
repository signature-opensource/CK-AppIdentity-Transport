using CK.Core;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity
{
    /// <summary>
    /// Parties are <see cref="ApplicationIdentityService"/> and <see cref="RemoteParty"/>.
    /// <see cref="PartyGroup"/> and <see cref="ExternalParty"/> are not parties.
    /// </summary>
    public abstract class ApplicationIdentityParty : ApplicationIdentityObject
    {
        internal ApplicationIdentityParty( ApplicationIdentityPartyConfiguration configuration, ApplicationIdentityService? appIdentityService )
            : base( configuration, appIdentityService )
        {
        }

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityPartyConfiguration"/> object.
        /// </summary>
        public new ApplicationIdentityPartyConfiguration Configuration => Unsafe.As<ApplicationIdentityPartyConfiguration>( _configuration );

        /// <summary>
        /// Gets the domain name.
        /// </summary>
        public string DomainName => Configuration.DomainName;

        /// <summary>
        /// Gets the environment name.
        /// </summary>
        public string EnvironmentName => Configuration.EnvironmentName;

        /// <summary>
        /// Gets the party name.
        /// </summary>
        public string PartyName => Configuration.PartyName;

        /// <summary>
        /// Gets the full name of this party.
        /// </summary>
        public NormalizedPath FullName => Configuration.FullName;

        /// <summary>
        /// Overridden to return the <see cref="FullName"/>.
        /// </summary>
        /// <returns>This <see cref="FullName"/>.</returns>
        public override string ToString() => FullName.Path;

    }
}
