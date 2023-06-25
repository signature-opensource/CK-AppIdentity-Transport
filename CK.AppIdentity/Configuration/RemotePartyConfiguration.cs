using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// Actual remote party configuration.
    /// </summary>
    public sealed class RemotePartyConfiguration : ApplicationIdentityPartyConfiguration
    {
        readonly string? _address;

        internal RemotePartyConfiguration( ImmutableConfigurationSection configuration,
                                           string domainName,
                                           NormalizedPath fullName,
                                           string? address,
                                           ref InheritedConfigurationProps props )
            : base( configuration, domainName, fullName, ref props )
        {
            Debug.Assert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                          && d == domainName && e == fullName.LastPart && p == fullName.Parts[^2] );

            _address = address;
        }

        /// <summary>
        /// Gets the address of this party.
        /// This is null if this application cannot reach the remote: this remote must be a server that accepts the remote as a client).
        /// </summary>
        public string? Address => _address;

    }
}
