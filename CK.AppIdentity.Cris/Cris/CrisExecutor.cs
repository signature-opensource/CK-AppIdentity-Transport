using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CK.Cris
{
    /// <summary>
    /// Base class to specialize with a specific <see cref="CrisExecutorRequest"/> type parameter
    /// to implement a new <see cref="ICrisExecutor"/>.
    /// </summary>
    /// <typeparam name="T">The request type that this executor handles.</typeparam>
    [CKTypeDefiner]
    public abstract partial class CrisExecutor<T> : ICrisExecutor where T : CrisExecutorRequest
    {
        readonly IServiceProvider _serviceProvider;
        readonly CommandValidator _commandValidator;
        readonly RawCommandExecutor _commandExecutor;
        readonly PerfectEventSender<ICrisExecutor> _parallelRunnerCountChanged;
        // We use null as the close signal for runners.
        // The _channel is used as the lock to manage runners.
        readonly Channel<object?> _channel;
        Runner? _last;
        int _runnerCount;
        int _plannedRunnerCount;
        // Ever increasing number.
        int _runnerNumber;

        public CrisExecutor( IServiceProvider serviceProvider,
                             CommandValidator commandValidator,
                             RawCommandExecutor commandExecutor )
        {
            _serviceProvider = serviceProvider;
            _commandValidator = commandValidator;
            _commandExecutor = commandExecutor;
            _channel = Channel.CreateUnbounded<object?>();
            _parallelRunnerCountChanged = new PerfectEventSender<ICrisExecutor>();
            _runnerCount = 1;
            _plannedRunnerCount = 1;
            _last = new Runner( this, 0, null );
        }

        public string EndpointRequestTypeName => typeof( T ).Name;

        public int ParrallelRunnerCount
        {
            get => _runnerCount;
            set
            {
                Throw.CheckOutOfRangeArgument( value >= 1 && value <= 1000 );
                Push( value );
            }
        }

        public PerfectEvent<ICrisExecutor> ParrallelRunnerCountChanged => _parallelRunnerCountChanged.PerfectEvent;

        public void Execute( ICrisExecutorEndPoint<T> endpoint, T request )
        {
            Push( new ExecuteJob( endpoint, request ) );
        }

        sealed record class ExecuteJob( ICrisExecutorEndPoint<T> Endpoint, T Request );

        void Push( object job ) => _channel.Writer.TryWrite( job );

        ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case ExecuteJob c: return HandleCommandAsync( monitor, c );
                case int count: return HandleSetRunnerCountAsync( monitor, count );
            }
            monitor.Error( $"Unhandled job type '{job.GetType()}'." );
            return default;
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
            // - The services can be resolved only once across Validation and Execution method.
            var step = "configuring services";
            try
            {
                using( monitor.CollectEntries( out var entries, LogLevelFilter.Warn, 200 ) )
                {
                    job.Endpoint.ConfigureServices( monitor, job.Request, services );
                    var v = CommandValidationResult.Create( entries );
                    if( !v.Success )
                    {
                        // At least one error occurred while configuring the services.
                        // Send the faulted validation result and we are done.
                        job.Endpoint.SendCrisValidationResult( monitor, job.Request, v );
                        return;
                    }
                }
                step = "validating";
                var validation = await _commandValidator.ValidateCommandAsync( monitor, services, job.Request.Payload );
                // Always send the CommandValidationResult even if it is successful.
                job.Endpoint.SendCrisValidationResult( monitor, job.Request, validation );
                // If validation fails, we are done.
                if( !validation.Success ) return;
                // Executing the command (handlers and post handlers).
                step = "executing";
                var result = await _commandExecutor.RawExecuteCommandAsync( services, job.Request.Payload );
                // Send the result. We are done.
                job.Endpoint.SendCommandResult( monitor, job.Request, result );
            }
            catch( Exception ex )
            {
                using( monitor.OpenError( $"While {step} command '{job.Request.Payload.CrisPocoModel.PocoName}'." ) )
                {
                    monitor.Trace( job.Request.Payload.ToString()!, ex );
                }
                // Send the error. We are done.
                job.Endpoint.SendCommandError( monitor, job.Request, ex );
            }
            finally
            {
                services.Dispose();
                await scoped.DisposeAsync();
            }
        }
    }
}
