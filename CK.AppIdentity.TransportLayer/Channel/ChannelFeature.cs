using CK.Core;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Base class for channel features.
    /// </summary>
    public abstract class ChannelFeature
    {
        readonly TransportLayerFeature _transportFeature;

        // Set by TransportLayerFeature.RegisterChannel on success.
        // On failure, the channel feature is not referenced by anybody.
        [AllowNull]
        internal string _baseProtocolName;

        protected ChannelFeature( TransportLayerFeature transportFeature )
        {
            _transportFeature = transportFeature;
        }

        /// <summary>
        /// Gets the <see cref="MessageProtocol.Name"/> that is handled by this channel.
        /// </summary>
        public string BaseProtocolName => _baseProtocolName;

        /// <summary>
        /// Gets the versioned protocols that are handled by this channel.
        /// </summary>
        public IEnumerable<MessageProtocol> SupportedProtocols => _transportFeature.RegisteredProtocols.Where( p => p.Name == _baseProtocolName );

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
        /// Gets the <see cref="TransportLayerFeature"/>.
        /// </summary>
        protected TransportLayerFeature Transport => _transportFeature;


        internal IMessageHandler EnsureMessageHandler( IActivityMonitor monitor, MessageProtocol protocol )
        {

            throw new NotImplementedException();
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
