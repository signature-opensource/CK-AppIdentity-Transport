using CK.Auth;
using CK.Core;
using CK.Cris;
using System;
using static CK.Core.CheckedWriteStream;

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

            public void ReturnCommandResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, CrisExecutor.ICrisExecutorPayload? result )
                => _feature.EndpointReturnCommandResult( monitor, request, result );

            public void ReturnCrisValidationResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, CrisValidationResult validationResult )
                => _feature.EndpointReturnCrisValidationResult( monitor, request, validationResult );

            public void ReturnEvent( IActivityMonitor monitor, CrisChannelExecutorRequest request, IEvent e )
                => _feature.EndpointReturnEvent( monitor, request, e );

        }

        void EndpointConfigureServices( IActivityMonitor monitor, CrisChannelExecutorRequest request, SimpleServiceContainer services )
        {
            if( request.AuthToken != null )
            {
                IAuthenticationInfo? authInfo = _tokenService.TryParseAuthenticationToken( request.AuthToken );
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

        void EndpointReturnCrisValidationResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, CrisValidationResult validationResult )
        {
            var h = CurrentHandler;
            if( h != null )
            {
                if( h.TrySendValidationMessage( request.IssuerToken.Key, validationResult ) )
                {
                    return;
                }
            }
            monitor.Warn( $"Connection to the caller '{Transport.Party.FullName}' is lost: unable to notify the validation result." );
        }

        void EndpointReturnCommandResult( IActivityMonitor monitor, CrisChannelExecutorRequest request, CrisExecutor.ICrisExecutorPayload? result )
        {
            var h = CurrentHandler;
            if( h != null )
            {
                if( h.TrySendResult( request.IssuerToken.Key, result ) )
                {
                    return;
                }
            }
            monitor.Warn( $"Connection to the caller '{Transport.Party.FullName}' is lost: unable to notify the final result of the command." );
        }

        void EndpointReturnEvent( IActivityMonitor monitor, CrisChannelExecutorRequest request, IEvent e )
        {
            var h = CurrentHandler;
            if( h != null )
            {
                if( h.TrySendCommandEvent( request.IssuerToken.Key, e ) )
                {
                    return;
                }
            }
            monitor.Warn( $"Connection to the caller '{Transport.Party.FullName}' is lost: unable to notify the event '{e.CrisPocoModel.PocoName}'." );
        }

    }

}
