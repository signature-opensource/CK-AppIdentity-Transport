using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// The local party of a <see cref="IApplicationIdentity"/>.
    /// </summary>
    public interface ILocalParty : IParty
    {
        /// <inheritdoc cref="LocalPartyConfiguration.Name"/>
        string Name { get; }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        LocalPartyConfiguration Configuration { get; }

    }
}
