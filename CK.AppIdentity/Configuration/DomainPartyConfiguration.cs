using CK.Core;
using System.Collections.Generic;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// A domain party: the last part of its DomainName is the same as its PartyName and
    /// most often defines its <see cref="Parties"/>.
    /// </summary>
    public sealed class DomainPartyConfiguration : ApplicationIdentityPartyConfiguration
    {
        readonly ApplicationIdentityPartyConfiguration[] _parties;

        internal DomainPartyConfiguration( ImmutableConfigurationSection configuration,
                                           string domainName,
                                           NormalizedPath fullName,
                                           ApplicationIdentityPartyConfiguration[] parties,
                                           ref InheritedConfigurationProps props )
            : base( configuration, domainName, fullName, ref props )
        {
            Debug.Assert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                          && d == domainName && p == fullName.Parts[^2] && e == fullName.LastPart
                          && p[0] == '$' && p.Substring(1) == fullName.Parts[^3] );
            _parties = parties;
        }

        /// <summary>
        /// Gets the subordinated configurations that can be:
        /// <list type="bullet">
        ///   <item><see cref="RemotePartyConfiguration"/> for a remote or external party.</item>
        ///   <item><see cref="DomainPartyConfiguration"/> for a subordinated domain.</item>
        /// </list>
        /// </summary>
        public IReadOnlyCollection<ApplicationIdentityPartyConfiguration> Parties => _parties;

    }
}
