using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.BlobChannel
{
    /// <summary>
    /// Base class for <see cref="MessageProtocolFeature"/> drivers.
    /// </summary>
    [CKTypeDefiner]
    public abstract class MessageProtocolFeatureDriver<T> : ApplicationIdentityFeatureDriver where T : MessageProtocolFeature
    {
        readonly MessageProtocolDirectoryService _messageProtocolDirectory;

        /// <summary>
        /// Initializes a new <see cref="MessageProtocolFeatureDriver{T}"/>.
        /// </summary>
        /// <param name="s">The application identity service.</param>
        /// <param name="messageProtocolDirectory">The message protocol directory service.</param>
        /// <param name="isAllowedByDefault">Whether the feature is opt-in or opt-out.</param>
        public MessageProtocolFeatureDriver( ApplicationIdentityService s,
                                             MessageProtocolDirectoryService messageProtocolDirectory,
                                             bool isAllowedByDefault )
            : base( s, isAllowedByDefault )
        {
            _messageProtocolDirectory = messageProtocolDirectory;
        }

        /// <summary>
        /// Gets the <see cref="MessageProtocolDirectoryService"/>.
        /// </summary>
        protected MessageProtocolDirectoryService MessageProtocolDirectory => _messageProtocolDirectory;

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
        {
            bool success = true;
            foreach( var r in ApplicationIdentityService.Remotes )
            {
                success &= SetupDynamicRemote( context, r );
            }
            return Task.FromResult( success );

        }

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty party )
        {
            return Task.FromResult( SetupDynamicRemote( context, party ) );
        }

        bool SetupDynamicRemote( FeatureLifetimeContext context, IRemoteParty r )
        {
            bool success = true;
            if( r.DomainApplicationIdentity != null )
            {
                foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                {
                    if( IsAllowedFeature( rSub ) )
                    {
                        success &= PlugFeature( context, rSub );
                    }
                }
            }
            else if( IsAllowedFeature( r ) )
            {
                success &= PlugFeature( context, r );
            }
            return success;
        }

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IRemoteParty party )
        {
            if( party.DomainName != CoreApplicationIdentity.DefaultDomainName )
            {
                if( party.DomainApplicationIdentity != null )
                {
                    foreach( var rSub in party.DomainApplicationIdentity.Remotes )
                    {
                        var t = rSub.GetFeature<T>();
                        t?.Teardown( context );
                    }
                }
                else
                {
                    var t = party.GetFeature<T>();
                    t?.Teardown( context );
                }
            }
            return Task.CompletedTask;
        }

        protected override Task TeardownAsync( FeatureLifetimeContext context )
        {
            foreach( var r in ApplicationIdentityService.Remotes )
            {
                var t = r.GetFeature<T>();
                t?.Teardown( context );
            }
            return Task.CompletedTask;
        }

        bool PlugFeature( FeatureLifetimeContext context, IRemoteParty r )
        {
            if( r.DomainName != CoreApplicationIdentity.DefaultDomainName )
            {
                var transport = r.GetFeature<TransportFeature>();
                // No Transport implies no communication.
                if( transport == null )
                {
                    context.Monitor.Warn( $"No Transport feature available on '{r.FullName}'. {FeatureName} cannot be setup." );
                    return true;
                }
                return PlugFeature( context, r, transport, _messageProtocolDirectory );
            }
            return true;
        }

        /// <summary>
        /// This is called when the feature is allowed on the remote and the <see cref="TransportFeature"/> is available:
        /// a configured <see cref="T"/> feature should be added to the <paramref name="party"/> if possible.
        /// </summary>
        /// <param name="context">The initialization context that exposes the monitor to use and its trampoline if needed.</param>
        /// <param name="transport">The transport feature of the party.</param>
        /// <param name="messageProtocolDirectory">The message protocol directory.</param>
        /// <returns>True on success (even if no feature has been added to the party), false if the initialization fails.</returns>
        abstract protected bool PlugFeature( FeatureLifetimeContext context,
                                             IRemoteParty party,
                                             TransportFeature transport,
                                             MessageProtocolDirectoryService messageProtocolDirectory );
    }

}
