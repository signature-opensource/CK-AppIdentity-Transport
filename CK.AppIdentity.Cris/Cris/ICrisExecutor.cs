using CK.Core;
using CK.PerfectEvent;

namespace CK.Cris
{
    /// <summary>
    /// A Cris executor handles <see cref="CrisExecutorCommand"/> in the background in the context
    /// of <see cref="ICrisExecutorEndPoint{T}"/>.
    /// </summary>
    [IsMultiple]
    public interface ICrisExecutor : ISingletonAutoService
    {
        /// <summary>
        /// Gets the type name of the <see cref="CrisExecutorCommand"/> that this
        /// <see cref="CrisExecutor{T}"/> handles.
        /// <para>
        /// Assuming that each end point provides a specific request type, this identifies
        /// the endpoint and its executor.
        /// </para>
        /// </summary>
        string EndpointRequestTypeName { get; }

        /// <summary>
        /// Gets or sets the number of parallel runners that handles the requests.
        /// It must be between 1 and 1000.
        /// </summary>
        int ParallelRunnerCount { get; set; }

        /// <summary>
        /// Raised whenever the <see cref="ParallelRunnerCount"/> changes.
        /// </summary>
        PerfectEvent<ICrisExecutor> ParallelRunnerCountChanged { get; }
    }
}
