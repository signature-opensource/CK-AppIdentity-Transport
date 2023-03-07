using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    public interface IApplicationIdentity
    {
        /// <summary>
        /// Gets the root application identity.
        /// This is this object is this is the root identity service.
        /// </summary>
        ApplicationIdentityService ApplicationIdentityService { get; }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        ApplicationIdentityConfiguration Configuration { get; }

        /// <inheritdoc cref="ApplicationIdentityConfiguration.DomainName"/>
        string DomainName { get; }

        /// <inheritdoc cref="ApplicationIdentityConfiguration.EnvironmentName"/>
        string EnvironmentName { get; }

        /// <summary>
        /// Gets the this local identity.
        /// </summary>
        ILocalParty Local { get; }

        /// <summary>
        /// Gets the remote parties.
        /// </summary>
        IReadOnlyCollection<IRemoteParty> Remotes { get; }

        /// <summary>
        /// Gets a task that is completed once all the <see cref="AppIdentityFeatureBuilder"/> have been
        /// initialized. Initialization errors are set on this task if exceptions occurred: awaiting this
        /// task will re-throw the initialization errors.
        /// <para>
        /// Use <see cref="Task.IsCompletedSuccessfully"/> to know if initialization has been successful.
        /// </para>
        /// </summary>
        Task FeatureBuildersInitialization { get; }

        /// <summary>
        /// Gets the features associated to this <see cref="IApplicationIdentity"/>.
        /// </summary>
        IEnumerable<object> Features { get; }

        /// <summary>
        /// Atomically (thread safe) adds a feature if it doesn't already exist.
        /// </summary>
        /// <param name="feature">The feature to add.</param>
        /// <returns>True if the feature has been added, false if the feature already exists.</returns>
        bool AddFeature( object feature );
    }
}
