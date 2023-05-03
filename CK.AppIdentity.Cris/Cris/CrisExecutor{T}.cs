using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace CK.Cris
{
    /// <summary>
    /// Base class to specialize with a specific <see cref="CrisExecutorRequest"/> type parameter
    /// to implement a new <see cref="ICrisExecutor"/>.
    /// </summary>
    /// <typeparam name="T">The request type that this executor handles.</typeparam>
    public abstract partial class CrisExecutor<T> : CrisExecutor where T : CrisExecutorRequest
    {
        readonly IServiceProvider _serviceProvider;
        readonly IPocoFactory<ICrisExecutorPayload> _resultFactory;
        readonly IPocoFactory<ICrisResultError> _errorResultFactory;
        readonly RawCrisValidator _commandValidator;
        readonly RawCrisExecutor _commandExecutor;

        public CrisExecutor( IServiceProvider serviceProvider,
                             RawCrisValidator commandValidator,
                             RawCrisExecutor commandExecutor )
        {
            _serviceProvider = serviceProvider;
            _resultFactory = serviceProvider.GetRequiredService<IPocoFactory<ICrisExecutorPayload>>();
            _errorResultFactory = serviceProvider.GetRequiredService<IPocoFactory<ICrisResultError>>();

            _commandValidator = commandValidator;
            _commandExecutor = commandExecutor;
        }

        /// <inheritdoc />
        public override string EndpointRequestTypeName => typeof( T ).Name;

        /// <summary>
        /// Accepts a request that will be executed in the background.
        /// </summary>
        /// <param name="endpoint">The endpoint that submits the request.</param>
        /// <param name="request">The request to send and execute.</param>
        public void Execute( ICrisExecutorEndPoint<T> endpoint, T request )
        {
            Push( new ExecuteJob( endpoint, request ) );
        }

        sealed record class ExecuteJob( ICrisExecutorEndPoint<T> Endpoint, T Request );

        private protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            if( job is ExecuteJob c ) return HandleCommandAsync( monitor, c );
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        async ValueTask HandleCommandAsync( IActivityMonitor monitor, ExecuteJob job )
        {
            using var log = monitor.StartDependentActivity( job.Request.IssuerToken );

            // Creates a scoped services from the global DI but wraps it into an interceptor
            // that can be configured by the EndPoint.
            // Adds the current monitor to this provider: it will be the monitor used
            // by validation and execution.
            var scoped = _serviceProvider.CreateAsyncScope();
            var services = new SimpleServiceContainer( scoped.ServiceProvider );
            services.Add( monitor );

            // TODO: This should be code generated for 2 reasons:
            // - The warnings of the ConfigureServices will appear in the validation result (currently they are lost).
            // - The services can be resolved only once across the Validation and Execution methods.
            var step = "configuring services for";
            try
            {
                using( monitor.CollectEntries( out var entries, LogLevelFilter.Warn, 200 ) )
                {
                    job.Endpoint.ConfigureServices( monitor, job.Request, services );
                    var v = CrisValidationResult.Create( entries );
                    if( !v.Success )
                    {
                        // At least one error occurred while configuring the services.
                        // Send the faulted validation result and we are done.
                        job.Endpoint.ReturnCrisValidationResult( monitor, job.Request, v );
                        return;
                    }
                }
                step = "validating";
                var validation = await _commandValidator.ValidateCrisPocoAsync( monitor, services, job.Request.Payload );
                // Always send the CrisValidationResult even if it is successful: this is the "execution started" signal.
                job.Endpoint.ReturnCrisValidationResult( monitor, job.Request, validation );
                // If validation fails, we are done.
                if( !validation.Success ) return;
                // Executing the command (handlers and post handlers).
                step = "executing";
                var result = await _commandExecutor.RawExecuteAsync( services, job.Request.Payload );
                // Send the result. We are done.
                var r = _resultFactory.Create();
                r.Result = result;
                job.Endpoint.ReturnCommandResult( monitor, job.Request, r );
            }
            catch( Exception ex )
            {
                using( monitor.OpenError( $"While {step} command '{job.Request.Payload.CrisPocoModel.PocoName}'." ) )
                {
                    monitor.Error( job.Request.Payload.ToString()!, ex );
                }
                // Send the error. We are done.
                var error = _errorResultFactory.Create( e => e.Errors.Add( ex.Message ) );
                // This duplicates the code above but if an exception occurs here (it will be caught and
                // log by the Runner), we want to dispose the services.
                var r = _resultFactory.Create();
                r.Result = error;
                job.Endpoint.ReturnCommandResult( monitor, job.Request, r );
            }
            finally
            {
                services.Dispose();
                await scoped.DisposeAsync();
            }
        }
    }
}
