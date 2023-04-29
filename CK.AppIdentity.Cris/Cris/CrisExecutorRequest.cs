using CK.AppIdentity.Cris;
using CK.Core;
using CK.Cris;

namespace CK.Cris
{
    /// <summary>
    /// Base class for any Cris request that can be specialized for specific end point.
    /// <para>
    /// This is used on the sender side (new requests or deserialized requests from a persistent store) and
    /// on the receiver side (by deserializing the incoming message payload). Specializations typically add
    /// specific data and should keep them internal.
    /// </para>
    /// <para>
    /// On the sender side, 
    /// </para>
    /// </summary>
    public abstract class CrisExecutorRequest
    {
        /// <summary>
        /// Initialize a new <see cref="CrisExecutorRequest"/> from its data (typically used when
        /// deserializing).
        /// </summary>
        /// <param name="payload">The event or command.</param>
        /// <param name="issuerToken">The issuer token.</param>
        protected CrisExecutorRequest( ICrisPoco payload, ActivityMonitor.DependentToken issuerToken )
        {
            Throw.CheckNotNullArgument( payload );
            Payload = payload;
            IssuerToken = issuerToken;
        }

        /// <summary>
        /// Initializes a new <see cref="CrisExecutorRequest"/> for an outgoing request event.
        /// </summary>
        /// <param name="payload">The event or command.</param>
        /// <param name="issuerToken">The issuer token.</param>
        protected CrisExecutorRequest( IOutgoingRequest request )
        {
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
