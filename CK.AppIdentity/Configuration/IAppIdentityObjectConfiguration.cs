using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace CK.AppIdentity
{

    /// <summary>
    /// Generalizes <see cref="ApplicationIdentityConfiguration"/>, <see cref="RemotePartyConfiguration"/> and <see cref="LocalPartyConfiguration"/>.
    /// </summary>
    public interface IAppIdentityObjectConfiguration
    {
        /// <summary>
        /// Gets a set of feature names that are disabled at this level.
        /// No duplicate and no <see cref="AllowFeatures"/> must appear in this set.
        /// </summary>
        IReadOnlySet<string> DisallowFeatures { get; }

        /// <summary>
        /// Gets a set of feature names that are enabled at this level.
        /// No duplicate and no <see cref="DisallowFeatures"/> must appear in this set.
        /// </summary>
        IReadOnlySet<string> AllowFeatures { get; }
    }

    /// <summary>
    /// Extends <see cref="IAppIdentityObjectConfiguration"/>.
    /// </summary>
    public static class AppIdentityObjectConfigurationExtensions
    {
        /// <summary>
        /// Computes whether a features is allowed at this level based on <paramref name="isAllowedAbove"/>
        /// and the content of <see cref="AllowFeatures"/> and <see cref="DisallowFeatures"/>.
        /// </summary>
        /// <param name="c">This configuration.</param>
        /// <param name="featureName">The feature name.</param>
        /// <param name="isAllowedAbove">Whether this feature is allowed by default.</param>
        /// <returns>True if the feature is allowed for this level.</returns>
        public static bool IsAllowedFeature( this IAppIdentityObjectConfiguration c, string featureName, bool isAllowedAbove )
        {
            if( isAllowedAbove )
            {
                return !c.DisallowFeatures.Contains( featureName );
            }
            return c.AllowFeatures.Contains( featureName );
        }

    }
}
