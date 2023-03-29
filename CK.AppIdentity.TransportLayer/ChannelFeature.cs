using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Base class for message protocol handlers.
    /// </summary>
    public abstract class ChannelFeature
    {
        readonly TransportLayerFeature _transportFeature;
        int _protocolNumber;

        protected ChannelFeature( TransportLayerFeature transportFeature )
        {
            _transportFeature = transportFeature;
        }

        /// <summary>
        /// Gets a <see cref="MessageProtocol.Name"/> if the protocol name based on the <see cref="ApplicationIdentityFeatureDriver.FeatureName"/>
        /// must not be used.
        /// </summary>
        internal protected virtual string? OverrideProtocolName => null;

        /// <summary>
        /// Gets an empty array by default.
        /// If multiple versions are supported, this must return the supported versions.
        /// The initial and default version is 0.
        /// </summary>
        internal protected virtual IEnumerable<ushort> Versions => Array.Empty<ushort>();

        /// <summary>
        /// Gets whether the protocol is specific to the party.
        /// Defaults to false.
        /// </summary>
        internal protected virtual bool IsPartySpecificProtocol => false;

        /// <summary>
        /// Gets the <see cref="TransportLayerFeature"/>.
        /// </summary>
        protected TransportLayerFeature Transport => _transportFeature;

        internal void Initialize( int protocolNumber )
        {
            _protocolNumber = protocolNumber;
        }

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
