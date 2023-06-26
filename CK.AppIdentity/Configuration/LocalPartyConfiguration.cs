using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// A local party is a "domain controller": the last part of its DomainName is the
    /// same as its PartyName. 
    /// </summary>
    public sealed class LocalPartyConfiguration : ApplicationIdentityPartyConfiguration
    {
        internal LocalPartyConfiguration( ImmutableConfigurationSection configuration,
                                          string domainName,
                                          NormalizedPath fullName,
                                          ref InheritedConfigurationProps props )
            : base( configuration, domainName, fullName, ref props )
        {
            Debug.Assert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                          && d == domainName && e == fullName.LastPart && p == fullName.Parts[^2] );
        }
    }
}
