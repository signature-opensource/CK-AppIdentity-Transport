using CK.Core;
using System.Collections.Generic;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// A tenant domain in the <see cref="ApplicationIdentityServiceConfiguration"/>: the last part
    /// of its DomainName is the same as its PartyName AND it has no "Address (otherwise it is a remote party).
    /// Most often it defines <see cref="Remotes"/> but this is allowed to be empty to support fully dynamic
    /// configuration.
    /// </summary>
    public class TenantDomainPartyConfiguration : ApplicationIdentityPartyConfiguration
    {
        readonly List<RemotePartyConfiguration> _remotes;

        internal TenantDomainPartyConfiguration( ImmutableConfigurationSection configuration,
                                                 string domainName,
                                                 NormalizedPath fullName,
                                                 List<RemotePartyConfiguration> remotes,
                                                 ref InheritedConfigurationProps props )
            : base( configuration, domainName, fullName, ref props )
        {
            Throw.DebugAssert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                          && d == domainName && p == fullName.Parts[^2] && e == fullName.LastPart
                          && p[0] == '$' && p.Substring(1) == fullName.Parts[^3] );
            _remotes = remotes;
        }

        /// <summary>
        /// Gets the remotes configurations.
        /// This can be empty.
        /// </summary>
        public IReadOnlyCollection<RemotePartyConfiguration> Remotes => _remotes;

    }
}
