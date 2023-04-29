using CK.Auth;
using CK.Core;
using CK.Cris;
using System;

namespace CK.AppIdentity.Cris
{
    public sealed partial class CrisChannelFeature
    {
        /// <summary>
        /// Implements the endpoint by relaying the calls to the methods below.
        /// We could have implemented this interface directly on the <see cref="CrisChannelFeature"/>
        /// but this is a hidden relay to fully hide this "Endpoint" aspect to the external world:
        /// this concerns the executor.
        /// </summary>
        sealed class CrisChannelEndpoint : ICrisExecutorEndPoint<CrisChannelExecutorRequest>
        {
            readonly CrisChannelFeature _feature;

            public CrisChannelEndpoint( CrisChannelFeature feature ) =>  _feature = feature;

            public void ConfigureServices( IActivityMonitor monitor, CrisChannelExecutorRequest request, SimpleServiceContainer services )
                => _feature.EndpointConfigureServices( monitor, request, services );

            public void SendCommandResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, object? result )
                => _feature.EndpointSendCommandResult( monitor, request, result );

            public void SendCrisValidationResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, CommandValidationResult validationResult )
                => _feature.EndpointSendCrisValidationResult( monitor, request, validationResult );

            public void SendEvent( IActivityMonitor monitor, CrisChannelExecutorRequest request, IEvent e )
                => _feature.EndpointSendEvent( monitor, request, e );

            public void SendCommandError( IActivityMonitor monitor, CrisChannelExecutorRequest request, Exception ex )
                => _feature.EndpointSendCommandError( monitor, request, ex );

        }

        void EndpointConfigureServices( IActivityMonitor monitor, CrisChannelExecutorRequest request, SimpleServiceContainer services )
        {
            IAuthenticationInfo? authInfo = null;
            if( request.AuthToken != null )
            {
                authInfo = _tokenService.TryParseAuthenticationToken( request.AuthToken );
                if( authInfo == null )
                {
                    monitor.Error( "Unable to parse Authentication token." );
                }
                else
                {
                    services.Add( authInfo );
                }
            }
        }

        void EndpointSendCrisValidationResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, CommandValidationResult validationResult )
        {
            var h = CurrentHandler;
            if( h != null )
            {
                
            }
        }

        void EndpointSendCommandResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, object? result )
        {
            throw new NotImplementedException();
        }

        void EndpointSendEvent( IActivityMonitor monitor, CrisChannelExecutorRequest request, IEvent e )
        {
            throw new NotImplementedException();
        }

        void EndpointSendCommandError( IActivityMonitor monitor, CrisChannelExecutorRequest request, Exception ex )
        {
            throw new NotImplementedException();
        }

    }

}
