using CK.AppIdentity.TransportLayer;
using CK.Core;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading.Tasks;

namespace CK.AppIdentity.BlobChannel
{
    /// <summary>
    /// Blob channels is a opt-in feature.
    /// </summary>
    public sealed class BlobChannelFeatureDriver : ApplicationIdentityFeatureDriver
    {
        readonly MessageProtocol _protocol;

        public BlobChannelFeatureDriver( ApplicationIdentityService s, MessageProtocolDirectoryService messageProtocolDirectory )
            : base( s, false )
        {
            _protocol = messageProtocolDirectory.Register( "Blob" );
        }

        protected override Task<bool> InitializeAsync( FeatureInitializatonContext context )
        {
            bool success = true;
            foreach( var r in ApplicationIdentityService.Remotes )
            {
                if( r.DomainApplicationIdentity != null )
                {
                    foreach( var rSub in r.DomainApplicationIdentity.Remotes )
                    {
                        if( IsAllowedFeature( rSub ) )
                        {
                            success &= PlugFeature( context.Monitor, rSub );
                        }
                    }
                }
                else
                {
                    if( IsAllowedFeature( r ) )
                    {
                        success &= PlugFeature( context.Monitor, r );
                    }
                }
            }
            return Task.FromResult( success );

        }

        protected override Task<bool> InitializeDynamicRemoteAsync( FeatureInitializatonContext context, IRemoteParty party )
        {
            throw new NotImplementedException();
        }

        bool PlugFeature( IActivityMonitor monitor, IRemoteParty r )
        {
            var transport = r.GetFeature<TransportFeature>();
            // No Transport implies no communication.
            if( transport == null )
            {
                monitor.Warn( $"No Transport feature available on '{r.FullName}'. Blob channel cannot be setup." );
                return true;
            }
            if( !transport.RegisterProtocol( monitor, _protocol ) ) return false;

            return true;
        }

    }

    public sealed class BlobChannel
    {
        readonly TransportFeature _transport;

        internal BlobChannel( TransportFeature transport )
        {
            _transport = transport;
        }

    }

}
