using CK.AppIdentity.Cris;
using CK.Core;
using CK.Cris;

namespace CK.Cris
{
    /// <summary>
    /// Base class for any Cris request that can be specialized for specific end point.
    /// <para>
    /// This is used on the receiver side (by deserializing the incoming message payload). Specializations typically add
    /// specific data and should keep them internal.
    /// </para>
    /// </summary>
    public abstract class CrisExecutorRequest
    {
        /// <summary>
        /// Initialize a new <see cref="CrisExecutorRequest"/> from its data (typically used when
        /// deserializing).
        /// </summary>
        /// <param name="payload">The command.</param>
        /// <param name="issuerToken">The issuer token.</param>
        protected CrisExecutorRequest( IAbstractCommand payload, ActivityMonitor.Token issuerToken )
        {
            Throw.CheckNotNullArgument( payload );
            Payload = payload;
            IssuerToken = issuerToken;
        }

        /// <summary>
        /// Gets the <see cref="ICommand"/> or <see cref="ICommand{TResult}"/>.
        /// </summary>
        public IAbstractCommand Payload { get; }

        /// <summary>
        /// Gets a token that identifies the initialization of this request.
        /// </summary>
        public ActivityMonitor.Token IssuerToken { get; }
    }
}
