using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Diagnostics;
using System.Threading;

namespace CK.AppIdentity.BlobChannel
{
    /// <summary>
    /// Base class for <see cref="ChannelFeature"/> drivers.
    /// </summary>
    [CKTypeDefiner]
    public abstract class ChannelFeatureDriver<T> : ApplicationIdentityFeatureDriver where T : ChannelFeature
    {
        /// <summary>
        /// Initializes a new <see cref="ChannelFeatureDriver{T}"/>.
        /// </summary>
        /// <param name="transport">The transport feature.</param>
        /// <param name="isAllowedByDefault">Whether the feature is opt-in or opt-out.</param>
        protected ChannelFeatureDriver( TransportFeatureDriver transport,
                                        bool isAllowedByDefault )
            : base( transport.ApplicationIdentityService, isAllowedByDefault )
        {
            if( FeatureName.Length <= 7 || !FeatureName.EndsWith( "Channel" ) )
            {
                Throw.InvalidOperationException( $"Feature '{FeatureName}' is a transport channel: it must end with 'Channel'. Type '{GetType():C}' must be renamed." );
            }
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
        {
            bool success = true;
            foreach( var r in context.GetAllLeafRemotes()
                                     .Where( r => r.DomainName != CoreApplicationIdentity.DefaultDomainName && IsAllowedFeature( r ) ) )
            {
                success &= PlugFeature( context, r );
            }
            return Task.FromResult( success );
        }

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty party )
        {
            bool success = true;
            foreach( var r in context.GetAllLeafRemotes()
                                     .Where( r => r.DomainName != CoreApplicationIdentity.DefaultDomainName && IsAllowedFeature( r ) ) )
            {
                success &= PlugFeature( context, r );
            }
            return Task.FromResult( success );
        }

        bool PlugFeature( FeatureLifetimeContext context, IRemoteParty r )
        {
            Debug.Assert( r.DomainName != CoreApplicationIdentity.DefaultDomainName );
            var transport = r.GetFeature<TransportFeature>();
            // No Transport implies no communication.
            if( transport == null )
            {
                context.Monitor.Warn( $"No Transport feature available on '{r.FullName}'. Feature '{FeatureName}' cannot be setup." );
                return true;
            }
            if( transport.Party != r )
            {
                context.Monitor.Fatal( $"Transport feature mismatch on '{r.FullName}': its transport is bound to '{transport.Party.FullName}'. Feature '{FeatureName}' cannot be setup." );
                return false;
            }
            // If TryCreateChannel returns false, this is an error.
            if( !TryCreateChannel( context, transport, out var channel ) ) return false;
            // But there may be no error and no channel.
            if( channel != null )
            {
                // RegisterChannel on the TransportFeature allocates the protocol number
                // for the channel.
                if( !transport.RegisterChannel( context.Monitor,
                                                channel,
                                                FeatureName,
                                                channel.OverrideProtocolName ?? FeatureName.Substring( 0, FeatureName.Length - 7 ),
                                                channel.Versions ) )
                {
                    return false;
                }
                r.AddFeature( channel );
            }
            return true;
        }

        protected override Task TeardownAsync( FeatureLifetimeContext context )
        {
            foreach( var r in context.GetAllLeafRemotes() )
            {
                var t = r.GetFeature<T>();
                t?.Teardown( context );
            }
            return Task.CompletedTask;
        }

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty party )
        {
            foreach( var r in context.GetAllLeafRemotes() )
            {
                var t = r.GetFeature<T>();
                t?.Teardown( context );
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// This is called when the feature is allowed on the remote and the <see cref="TransportFeature"/> is available:
        /// a configured <see cref="T"/> feature should be created if possible.
        /// </summary>
        /// <param name="context">The initialization context that exposes the monitor to use and its trampoline if needed.</param>
        /// <param name="transport">The transport feature of the party.</param>
        /// <param name="channel">Channel feature to be added to the <see cref="TransportFeature.Party"/>.</param>
        /// <returns>True on success (even if <paramref name="channel"/> is null), false if the whole configuration must fail.</returns>
        abstract protected bool TryCreateChannel( FeatureLifetimeContext context,
                                                  TransportFeature transport,
                                                  out T? channel );
    }

}
