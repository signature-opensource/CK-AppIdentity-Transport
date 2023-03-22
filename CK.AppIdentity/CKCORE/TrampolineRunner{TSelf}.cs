using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace CK.Core
{
    /// <summary>
    /// Abstract execution context for asynchronous and synchronous actions that provide them with a shared <see cref="Memory"/>,
    /// a <see cref="Monitor"/>, a <see cref="Trampoline"/> where action can enqueue one or more actions, error or finally handlers.
    /// A runner can be executed only once and is not thread safe.
    /// <para>
    /// This base class uses the (not funny) pattern of being parameterized by itself.
    /// It must be specialized with its own specialization to support additional features.
    /// </para>
    /// <para>
    /// Once specialized for a typed execution context, the modular way to extend this is simply to use extension methods backed by
    /// the <see cref="Memory"/>.
    /// </para>
    /// </summary>
    public abstract class TrampolineRunner<TSelf> : IAsyncDisposable where TSelf : TrampolineRunner<TSelf>
    {
        readonly Trampoline<TSelf> _reg;
        readonly IActivityMonitor _monitor;
        IDictionary<object, object>? _memory;
        readonly bool _callMemoryDisposable;
        Result _result;
        int _execFlag;
        bool? _stopOnFirstError;

        /// <summary>
        /// Captures <see cref="ExecuteAsync(bool)"/> result.
        /// </summary>
        public enum Result
        {
            /// <summary>
            /// No exception at all have been thrown.
            /// </summary>
            TotalSuccess,

            /// <summary>
            /// An action thrown an exception. Error and finally handlers have been called. 
            /// </summary>
            Error = 1,

            /// <summary>
            /// At least one success handler thrown an exception.
            /// </summary>
            HasSuccessException = 2,

            /// <summary>
            /// At least one error handler thrown an exception.
            /// </summary>
            HasErrorException = 4,

            /// <summary>
            /// At least one finally handler thrown an exception.
            /// </summary>
            HasFinallyException = 8,
        }

        /// <summary>
        /// Initializes an asynchronous execution context.
        /// By default all disposable <see cref="Memory"/>'s values are disposed with <see cref="IAsyncDisposable.DisposeAsync"/> or <see cref="IDisposable.Dispose"/>.
        /// </summary>
        /// <param name="monitor">The monitor that must be used.</param>
        /// <param name="trampoline">
        /// Optional existing trampoline. When null, a new <see cref="Trampoline"/> is automatically created.
        /// </param>
        protected TrampolineRunner( IActivityMonitor monitor, Trampoline<TSelf>? trampoline = null )
        {
            Throw.CheckNotNullArgument( monitor );
            _reg = (trampoline ?? new Trampoline<TSelf>()).AcquireOnce( this );
            _callMemoryDisposable = true;
            _monitor = monitor;
        }

        /// <summary>
        /// Initializes an execution context bound to an external memory.
        /// </summary>
        /// <param name="monitor">The monitor that must be used.</param>
        /// <param name="trampoline">Optional existing trampoline.</param>
        /// <param name="externalMemory">External memory.</param>
        /// <param name="callMemoryDisposable">
        /// True to call <see cref="IAsyncDisposable.DisposeAsync"/> or <see cref="IDisposable.Dispose"/> on
        /// all disposable <see cref="Memory"/>'s values.
        /// </param>
        protected TrampolineRunner( IActivityMonitor monitor, Trampoline<TSelf>? trampoline, IDictionary<object, object> externalMemory, bool callMemoryDisposable )
            : this( monitor, trampoline )
        {
            Throw.CheckNotNullArgument( externalMemory );
            _memory = externalMemory;
            _callMemoryDisposable = callMemoryDisposable;
        }

        /// <summary>
        /// Gets whether this runner is disposed.
        /// Calling <see cref="ExecuteAsync(bool)"/> automatically disposes it.
        /// </summary>
        public bool IsDisposed => _execFlag == 2;

        /// <summary>
        /// Get the current result. This is updated as soon as errors occurred.
        /// </summary>
        public Result CurrentResult => _result;

        /// <summary>
        /// Gets whether <see cref="ExecuteAsync(bool)"/> (true) or <see cref="ExecuteAllAsync(bool)"/> (false)
        /// has been called. This is null until one of these functions have been called.
        /// </summary>
        public bool? StopOnFirstError => _stopOnFirstError;

        /// <summary>
        /// Gets a memory that can be used to share state between actions.
        /// The registered values that support <see cref="IDisposable"/> or <see cref="IAsyncDisposable"/> will be
        /// automatically disposed when this context is <see cref="DisposeAsync"/> (except when using the special
        /// constructor <see cref="AsyncExecutionContext(IActivityMonitor,IDictionary{object, object},bool)"/>).
        /// </summary>
        public IDictionary<object, object> Memory
        {
            get
            {
                // Ok, there's a race condition here but this object is absolutely not
                // intended to be thread safe. This the _execFlag and Interlocked operation are
                // only here to detect misuses, not to provide a strong guaranty.
                Throw.CheckState( !IsDisposed );
                return _memory ?? (_memory = new Dictionary<object, object>());
            }
        }

        /// <summary>
        /// Gets the monitor to use.
        /// </summary>
        public IActivityMonitor Monitor => _monitor;

        /// <summary>
        /// Gets the trampoline where Actions, error, success and/or finally handlers can be registered
        /// even when <see cref="ExecuteAsync(bool)"/> is called.
        /// </summary>
        public Trampoline<TSelf> Trampoline => _reg;

        /// <summary>
        /// Executes the currently enlisted actions, optionally in reverse order.
        /// This stops on the first error.
        /// <list type="bullet">
        /// <item>
        /// On success the registered finally handlers are called (any exception raised by finally handlers are logged and ignored).
        /// </item>
        /// <item>
        /// On the first exception thrown by an action, the other actions are skipped and the registered error handlers and then the finally handlers are called
        /// (any exception raised by error or finally handlers are logged and ignored).
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="reverseInitialActions">
        /// True to revert the initial action list: the last registered action will be the first to be called.
        /// </param>
        /// <returns>The first exception that occurred or null on success.</returns>
        public async Task<Result> ExecuteAsync( bool reverseInitialActions = false )
        {
            await DoExecuteAsync( reverseInitialActions, false );
            return _result;
        }

        /// <summary>
        /// Executes all the currently enlisted actions (optionally in reverse order) regardless of whether they fail or not
        /// and returns null on success.
        /// On error the single exception or an <see cref="AggregateException"/> with multiple exceptions is returned.
        /// <para>
        /// Note that during the execution, <see cref="StopOnFirstError"/> and the <see cref="CurrentResult"/> are available:
        /// an action can know that it is being executed in this mode and that one or more previous actions have failed.
        /// </para>
        /// </summary>
        /// <param name="reverseInitialActions">
        /// True to revert the initial action list: the last registered action will be the first to be called.
        /// </param>
        /// <returns>Null on success otherwise the single exception or an <see cref="AggregateException"/> with multiple exceptions.</returns>
        public Task<Exception?> ExecuteAllAsync( bool reverseInitialActions = false ) => DoExecuteAsync( reverseInitialActions, true );

        async Task<Exception?> DoExecuteAsync( bool reverseInitialActions, bool executeAll )
        {
            if( Interlocked.CompareExchange( ref _execFlag, 1, 0 ) != 0 )
            {
                Throw.InvalidOperationException( "This trampoline has already been executed or disposed." );
            }
            _stopOnFirstError = !executeAll;
            Debug.Assert( _result == Result.TotalSuccess );

            // ExecuteAll state.
            List<Exception>? executeAllErrors = null;
            int executeAllFalseCount = 0;

            var actions = _reg._actions;
            if( reverseInitialActions ) actions.Reverse();
            using( _monitor.OpenInfo( $"{actions.Count} initial actions{(reverseInitialActions ? " in reverse order" : "")}." ) )
            {
                var self = (TSelf)this;
                int doneCount = 0;
                try
                {
                    int roundNumber = 0;
                    int roundCount;
                    while( (roundCount = actions.Count - doneCount) > 0 )
                    {
                        using( Monitor.OpenTrace( $"Executing round n°{++roundNumber} with {roundCount} actions." ) )
                        {
                            while( --roundCount >= 0 )
                            {
                                if( executeAll )
                                {
                                    try
                                    {
                                        if( !await ExecuteInitialAction( self, actions[doneCount] ).ConfigureAwait( false ) )
                                        {
                                            _result |= Result.Error;
                                            ++executeAllFalseCount;
                                        }
                                    }
                                    catch( Exception e )
                                    {
                                        _result |= Result.Error;
                                        executeAllErrors ??= new List<Exception>();
                                        executeAllErrors.Add( e );
                                    }
                                }
                                else if( !await ExecuteInitialAction( self, actions[doneCount] ).ConfigureAwait( false ) )
                                {
                                    _result |= Result.Error;
                                    break;
                                }
                                ++doneCount;
                            }
                        }
                    }
                    if( _result == Result.TotalSuccess )
                    {
                        var onSuccess = _reg._onSuccess;
                        if( onSuccess != null )
                        {
                            using( _monitor.OpenTrace( $"Calling {onSuccess.Count} success handlers." ) )
                            {
                                if( !await RaiseSuccessAsync( onSuccess ).ConfigureAwait( false ) ) _result |= Result.HasSuccessException;
                            }
                        }
                    }
                    else
                    {
                        await ExecuteOnError( actions, doneCount, null ).ConfigureAwait( false );
                    }
                }
                catch( Exception ex )
                {
                    await ExecuteOnError( actions, doneCount, ex ).ConfigureAwait( false );
                }
                finally
                {
                    if( _reg._onFinally != null )
                    {
                        using( _monitor.OpenInfo( $"Calling {_reg._onFinally.Count} finally handlers." ) )
                        {
                            if( !await RaiseFinallyAsync( _reg._onFinally ).ConfigureAwait( false ) ) _result |= Result.HasFinallyException;
                        }
                    }
                }
            }
            Interlocked.Exchange( ref _execFlag, 2 );
            await DoDisposeAsync();

            if( executeAllFalseCount != 0 )
            {
                executeAllErrors ??= new List<Exception>();
                executeAllErrors.Add( new CKException( $"{executeAllFalseCount} out of {actions.Count} actions returned false." ) );
            }
            return executeAllErrors != null
                                    ? (executeAllErrors.Count == 1 ? executeAllErrors[0] : new AggregateException( executeAllErrors ))
                                    : null; ;
        }


        async Task ExecuteOnError( List<object> actions, int doneCount, Exception? ex )
        {
            _result |= Result.Error;
            using( _monitor.OpenError( $"Error, leaving {actions.Count - doneCount - 1} not executed actions.", ex ) )
            {
                if( _reg._onError == null ) _monitor.Trace( "There is no registered error handler." );
                else
                {
                    using( _monitor.OpenInfo( $"Calling {_reg._onError.Count} error handlers." ) )
                    {
                        if( !await RaiseErrorAsync( _reg._onError, ex ).ConfigureAwait( false ) ) _result |= Result.HasErrorException;
                    }
                }
            }
        }

        /// <summary>
        /// Disposes this execution context.
        /// </summary>
        /// <returns>The awaitable.</returns>
        public ValueTask DisposeAsync()
        {
            return Interlocked.CompareExchange( ref _execFlag, 2, 0 ) == 0
                    ? DoDisposeAsync()
                    : default;
        }

        async ValueTask DoDisposeAsync()
        {
            if( _callMemoryDisposable && _memory != null )
            {
                foreach( var kv in _memory )
                {
                    try
                    {
                        if( kv.Value is IAsyncDisposable ad ) await ad.DisposeAsync().ConfigureAwait( false );
                        else if( kv.Value is IDisposable d ) d.Dispose();
                    }
                    catch( Exception ex )
                    {
                        _monitor.Error( $"While disposing {GetType():C}'s memory [{Safe( kv.Key )}] = {Safe( kv.Value )}.", ex );
                    }
                }

                static string Safe( object? o )
                {
                    try
                    {
                        return o?.ToString() ?? "<null>";
                    }
                    catch( Exception ex )
                    {
                        return $"<Exception '{ex.Message}' while calling ToString() on a '{o?.GetType().Name}'>";
                    }
                }
            }
        }

        static async ValueTask<bool> ExecuteInitialAction( TSelf t, object o )
        {
            switch( o )
            {
                case Func<TSelf, bool> a: return a( t );
                case Func<TSelf, Task<bool>> a: return await a( t ).ConfigureAwait( false );
                case Func<TSelf, ValueTask<bool>> a: return await a( t ).ConfigureAwait( false );
                case Action<TSelf> a: a( t ); return true;
                case Func<TSelf, ValueTask> a: await a( t ).ConfigureAwait( false ); return true;
                default:
                    Debug.Assert( o is Func<TSelf, Task> );
                    await ((Func<TSelf, Task>)o)( t ).ConfigureAwait( false );
                    return true;
            }
        }

        /// <summary>
        /// Executes the registered success handlers. This never throws.
        /// </summary>
        /// <param name="success">The success handlers.</param>
        /// <returns>False if a handler thrown.</returns>
        async Task<bool> RaiseSuccessAsync( List<Func<TSelf, Task>> success )
        {
            _reg.SetHandlingSuccess();
            bool result = true;
            int doneCount = 0;
            int roundNumber = 0;
            int roundCount;
            while( (roundCount = success.Count - doneCount) > 0 )
            {
                using( Monitor.OpenTrace( $"Executing Success handlers round n°{++roundNumber} with {roundCount} handlers." ) )
                {
                    for( int i = 0; i < roundCount; ++i )
                    {
                        try
                        {
                            await success[doneCount++].Invoke( (TSelf)this ).ConfigureAwait( false );
                        }
                        catch( Exception ex )
                        {
                            result = false;
                            _monitor.Error( $"While executing success handler. This is ignored.", ex );
                        }
                    }
                }
            }
            _reg.ClearHandling();
            return result;
        }

        /// <summary>
        /// Executes the error handlers. Never throws.
        /// </summary>
        /// <param name="errors">The error handlers.</param>
        /// <param name="ex">The exception that has been raised by the action.</param>
        /// <returns>False if a handler thrown.</returns>
        async Task<bool> RaiseErrorAsync( List<Func<TSelf, Exception?, Task>> errors, Exception? ex )
        {
            _reg.SetHandlingError();
            bool result = true;
            int doneCount = 0;
            int roundNumber = 0;
            int roundCount;
            while( (roundCount = errors.Count - doneCount) > 0 )
            {
                using( Monitor.OpenTrace( $"Executing Error handling round n°{++roundNumber} with {roundCount} handlers." ) )
                {
                    for( int i = 0; i < roundCount; ++i )
                    {
                        try
                        {
                            await errors[doneCount++].Invoke( (TSelf)this, ex ).ConfigureAwait( false );
                        }
                        catch( Exception exError )
                        {
                            result = false;
                            _monitor.Error( $"While handling error. This is ignored.", exError );
                        }
                    }
                }
            }
            _reg.ClearHandling();
            return result;
        }

        /// <summary>
        /// Executes the registered finally actions. This never throws.
        /// </summary>
        /// <param name="final">The final actions to execute.</param>
        /// <returns>False if a handler thrown.</returns>
        async Task<bool> RaiseFinallyAsync( List<Func<TSelf, Task>> final )
        {
            _reg.SetHandlingFinally();
            var result = true;
            int doneCount = 0;
            int roundNumber = 0;
            int roundCount;
            while( (roundCount = final.Count - doneCount) > 0 )
            {
                using( Monitor.OpenTrace( $"Executing Final handlers round n°{++roundNumber} with {roundCount} handlers." ) )
                {
                    for( int i = 0; i < roundCount; ++i )
                    {
                        try
                        {
                            await final[doneCount++].Invoke( (TSelf)this ).ConfigureAwait( false );
                        }
                        catch( Exception ex )
                        {
                            result = false;
                            _monitor.Error( $"While executing final handler. This is ignored.", ex );
                        }
                    }
                }
            }
            _reg.ClearHandling();
            return result;
        }

    }


}
