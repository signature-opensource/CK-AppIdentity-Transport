using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity
{
    public sealed class V2RemotePartyConfiguration : V2AppIdentityObjectConfiguration
    {
        readonly string _partyName;
        readonly string? _address;

        internal V2RemotePartyConfiguration( ImmutableConfigurationSection configuration,
                                            string domainName,
                                            NormalizedPath fullName,
                                            string? address,
                                            ref InheritedConfigurationProps props )
            : base( configuration, domainName, fullName, ref props )
        {
            Debug.Assert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                          && d == domainName && e == fullName.LastPart && p == fullName.Parts[^2] );

            _partyName = fullName.Parts[^2]; _address = address;
        }

        /// <summary>
        /// Gets the name of this remote party.
        /// </summary>
        public string PartyName => _partyName;

        /// <summary>
        /// Gets the address of this party.
        /// This is null if this application cannot reach the remote: this remote must be a server that accepts the remote as a client).
        /// </summary>
        public string? Address => _address;

    }
}
