using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity
{
    public sealed class V2LocalPartyConfiguration : V2AppIdentityObjectConfiguration
    {
        readonly string _partyName;

        V2LocalPartyConfiguration( ImmutableConfigurationSection configuration,
                                   string domainName,
                                   NormalizedPath fullName,
                                   ref InheritedConfigurationProps props )
            : base( configuration, domainName, fullName, ref props )
        {
            Debug.Assert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                          && d == domainName && e == fullName.LastPart && p == fullName.Parts[^2] );

            _partyName = fullName.Parts[^2];
        }

        /// <summary>
        /// Gets this party name. This is "$Local" for the <see cref="V2ApplicationIdentityConfiguration"/>
        /// and the "domain controller name" for <see cref="V2DomainConfiguration"/>.
        /// </summary>
        public string PartyName => _partyName;

        internal static V2LocalPartyConfiguration? Create( IActivityMonitor monitor,
                                                         ImmutableConfigurationSection configuration,
                                                         string domainName,
                                                         string environmentName,
                                                         bool isRootAppLocal,
                                                         ref InheritedConfigurationProps inheritedProps )
        {
            const string noKeyReason = "all naming of 'Local' is given by the domain definition above.";
            // Caution: we use non short-circuiting & here!
            bool success = InheritedConfigurationProps.TryCreate( monitor, inheritedProps, configuration, out var props )
                           & configuration.CheckNotExist( monitor, "FullName", noKeyReason )
                           & configuration.CheckNotExist( monitor, "DomainName", noKeyReason )
                           & configuration.CheckNotExist( monitor, "PartyName", noKeyReason )
                           & configuration.CheckNotExist( monitor, "EnvironmentName", noKeyReason );
            if( !success ) return null;
            string localName;
            if( isRootAppLocal ) localName = "Local";
            else
            {
                int idx = domainName.IndexOf( '/' );
                localName = idx < 0 ? domainName : domainName.Substring( idx + 1 );
            }
            return new V2LocalPartyConfiguration( configuration,
                                                 domainName,
                                                 $"{domainName}/${localName}/{environmentName}",
                                                 ref props );
        }

    }
}
