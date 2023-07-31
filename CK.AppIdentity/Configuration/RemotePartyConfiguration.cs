using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// Remote or External party configuration.
    /// The Address is always optional.
    /// <para>
    /// An external party is in the domain "External", it may have an Address or not and its
    /// <see cref="ApplicationIdentityPartyConfiguration.EnvironmentName"/> is mostly irrelevant.
    /// </para>
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
            Throw.DebugAssert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                          && d == domainName && e == fullName.LastPart && p == fullName.Parts[^2] );

            _address = address;
        }

        /// <summary>
        /// Gets whether this is an External party.
        /// </summary>
        public bool IsExternalParty => ReferenceEquals( FullName.Path, "External" );

        /// <summary>
        /// Gets the address of this party.
        /// This is null if this application cannot reach the remote: this remote must be a server that accepts the remote as a client).
        /// </summary>
        public string? Address => _address;

    }
}
