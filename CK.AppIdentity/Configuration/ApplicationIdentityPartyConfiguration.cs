using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// Parties are named objects.
    /// It can be the root application identity (the local party), a remote or external party, or a
    /// local party that "controls" a Domain.
    /// </summary>
    public abstract class ApplicationIdentityPartyConfiguration : ApplicationIdentityObjectConfiguration
    {
        readonly string _domainName;
        readonly string _partyName;
        readonly string _environmentName;
        readonly NormalizedPath _fullName;

        internal ApplicationIdentityPartyConfiguration( ImmutableConfigurationSection configuration,
                                                        string domainName,
                                                        NormalizedPath fullName,
                                                        ref InheritedConfigurationProps props )
            : base( configuration, ref props )
        {
            Debug.Assert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                            && d == domainName && e == fullName.LastPart && p == fullName.Parts[^2] );

            _domainName = domainName;
            _partyName = fullName.Parts[^2];
            _environmentName = fullName.LastPart;
            _fullName = fullName;
        }

        /// <summary>
        /// Gets the domain name.
        /// </summary>
        public string DomainName => _domainName;

        /// <summary>
        /// Gets the name of this party.
        /// </summary>
        public string PartyName => _partyName;

        /// <summary>
        /// Gets the environment name.
        /// </summary>
        public string EnvironmentName => _environmentName;

        /// <summary>
        /// Gets the full name of this object.
        /// </summary>
        public NormalizedPath FullName => _fullName;

    }
}
