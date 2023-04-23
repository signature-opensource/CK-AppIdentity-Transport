using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Base class for channel features.
    /// </summary>
    public abstract class ChannelFeature
    {
        readonly TransportFeature _transportFeature;

        // Set by TransportLayerFeature.RegisterChannel on success (OverrideProtocolName or derived from the concrete type name).
        // On failure, the channel feature is not referenced by anybody.
        [AllowNull]
        internal string _baseProtocolName;
        // Set by TransportLayerFeature.CloseChannelRegistration once the protocols have been
        // successfully registered and its number (1..MessageProtocolMap.MaxCount) is known.
        internal int _protocolNumber;

        PeerProtocolHandler? _firstHandler;
        PeerProtocolHandler? _currentHandler;

        protected ChannelFeature( TransportFeature transportFeature )
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
        /// Gets the underlying <see cref="TransportFeature"/>.
        /// </summary>
        public TransportFeature Transport => _transportFeature;

        /// <summary>
        /// Gets the current handler.
        /// </summary>
        protected PeerProtocolHandler? CurrentHandler => _currentHandler; 

        internal PeerProtocolHandler EnsureCurrentHandler( IActivityMonitor monitor, TransportController endPoint, MessageProtocol protocol )
        {
            Debug.Assert( protocol.Name == _baseProtocolName );
            Debug.Assert( (protocol.Version == 0 && !Versions.Any()) || Versions.Contains( protocol.Version ) );
            // Fast path: no change.
            if( _currentHandler != null && _currentHandler.Protocol == protocol )
            {
                return _currentHandler;
            }
            // Finds an existing handler.
            var h = _firstHandler;
            while( h != null )
            {
                if( h.Protocol == protocol ) break;
                h = h._nextHandler;
            }
            // Creates a new handler.
            if( h == null )
            {
                var factory = new OutgoingMessageFactory( _protocolNumber, protocol );
                var c = new PeerProtocolHandler.CreateParameters( _firstHandler, endPoint, factory );
                _firstHandler = h = CreateHandler( monitor, ref c );
            }
            SetCurrentHandler( monitor, h );
            return h;
        }

        internal void OnConnectionLost( IActivityMonitor monitor )
        {
            SetCurrentHandler( monitor, null );
        }

        void SetCurrentHandler( IActivityMonitor monitor, PeerProtocolHandler? h )
        {
            var prev = _currentHandler;
            if( prev != h )
            {
                _currentHandler = h;
                OnCurrentHandlerChanged( monitor, prev, h );
            }
        }

        /// <summary>
        /// Called when the remote party is destroyed.
        /// Does nothing by default.
        /// </summary>
        /// <param name="context">The context that exposes the monitor to use and its trampoline if needed.</param>
        internal protected virtual void Teardown( FeatureLifetimeContext context )
        {
        }

        /// <summary>
        /// Must create a handler for the <see cref="PeerProtocolHandler.CreateParameters.Protocol"/> in the appropriate version.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="c">The opaque creation parameters.</param>
        /// <returns>A handler for the protocol.</returns>
        protected abstract PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c );

        /// <summary>
        /// Called whenever the <see cref="CurrentHandler"/> changed.
        /// Does nothing by default.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="previous">The previous handler.</param>
        /// <param name="current">The current handler.</param>
        protected virtual void OnCurrentHandlerChanged( IActivityMonitor monitor, PeerProtocolHandler? previous, PeerProtocolHandler? current )
        {
        }

    }

}
