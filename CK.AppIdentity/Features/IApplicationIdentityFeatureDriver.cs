using CK.Core;

namespace CK.AppIdentity
{
    /// <summary>
    /// Multiple interface service of <see cref="ApplicationIdentityFeatureDriver"/>.
    /// </summary>
    [IsMultiple]
    public interface IApplicationIdentityFeatureDriver : ISingletonAutoService
    {
        /// <summary>
        /// Gets this feature name.
        /// </summary>
        string FeatureName { get; }

        /// <summary>
        /// Gets whether this feature is allowed by default.
        /// </summary>
        bool IsRootAllowed { get; }
    }
}
