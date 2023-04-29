using CK.Core;
using CK.Cris;

namespace CK.Cris
{
    /// <summary>
    /// Base class for any Cris request that can be specialized for specific end point.
    /// </summary>
    public class CrisExecutorRequest
    {
        /// <summary>
        /// Initialize a new <see cref="CrisExecutorRequest"/> with the event or command
        /// that must be handled.
        /// </summary>
        /// <param name="payload">The event or command.</param>
        /// <param name="issuerToken">The issuer token.</param>
        public CrisExecutorRequest( ICrisPoco payload, ActivityMonitor.DependentToken issuerToken )
        {
            Throw.CheckNotNullArgument( payload );
            Payload = payload;
            IssuerToken = issuerToken;
        }

        /// <summary>
        /// Gets the <see cref="ICrisEvent"/>, <see cref="ICommand"/> or <see cref="ICommand{TResult}"/>.
        /// </summary>
        public ICrisPoco Payload { get; }

        /// <summary>
        /// Gets a token that identifies the initialization of this request.
        /// </summary>
        public ActivityMonitor.DependentToken IssuerToken { get; }
    }
}
