using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Base class for message protocol handlers.
    /// </summary>
    public abstract class MessageProtocolFeature
    {
        internal readonly MessageProtocolFeature? _nextProtocol;
        readonly TransportFeature _transportFeature;

        protected MessageProtocolFeature( TransportFeature transportFeature )
        {
            _nextProtocol = transportFeature._firstProtocol;
            transportFeature._firstProtocol = this;
            _transportFeature = transportFeature;
        }

        internal bool Initialize( IActivityMonitor monitor )
        {
            bool atLeastOne = false;
            foreach( var p in Protocols )
            {
                if( p == null || p == MessageProtocol.ZeroProtocol )
                {
                    monitor.Error( $"Invalid protocol in '{GetType():C}.Protocols'." );
                    return false;
                }
                if( !_transportFeature.RegisterProtocol( monitor, p ) )
                {
                    return false;
                }
                atLeastOne = true;
            }
            if( !atLeastOne )
            {
                monitor.Error( $"No protocol in '{GetType():C}.Protocols'." );
                return false;
            }
            return true;
        }

        /// <summary>
        /// Must provide at least one <see cref="MessageProtocol"/> that this feature handles.
        /// </summary>
        abstract protected IEnumerable<MessageProtocol> Protocols { get; }

        /// <summary>
        /// Extension point that validates the final negotiated protocols between this party and the other one.
        /// This enables a new transport to be totally rejected if the final protocols are not satisfying.
        /// Returns true at this level: by default, even if none of the <see cref="Protocols"/> for this feature
        /// exist, the transport is accepted and it is up to this feature to handle its unavailability.
        /// </summary>
        /// <param name="logger">The logger that must be used to explicit errors or warnings.</param>
        /// <param name="protocols">The final set of protocols that will be available on the transport.</param>
        /// <returns>True to accept the protocols (and deals with them), false to reject the transport.</returns>
        internal protected virtual bool ValidateNegotiatedProtocols( IActivityLogger logger, IReadOnlyList<MessageProtocol> protocols )
        {
            return true;
        }

        /// <summary>
        /// Gets the <see cref="TransportFeature"/>.
        /// </summary>
        protected TransportFeature Transport => _transportFeature;

        /// <summary>
        /// Called when the remote party is destroyed.
        /// Does nothing by default.
        /// </summary>
        /// <param name="context">The context that exposes the monitor to use and its trampoline if needed.</param>
        internal protected virtual void Teardown( FeatureLifetimeContext context )
        {
        }

    }

}
