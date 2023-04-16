using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Core.CompletionSource;

namespace CK.Core
{
    /// <summary>
    /// Execution context for asynchronous and synchronous actions that provide them with an optional
    /// shared <see cref="Memory"/>, and a <see cref="Trampoline"/> where action can enqueue one or more actions,
    /// error or finally handlers.
    /// A runner can be executed only once and is not thread safe.
    /// </summary>
    public sealed class BasicTrampolineRunner
    {
        readonly BasicTrampoline _reg;
        IDictionary<object, object>? _memory;
        TrampolineResult _result;
        int _execFlag;
        Exception? _error;
        bool? _stopOnFirstError;

        /// <summary>
        /// Initializes an <see cref="BasicTrampolineRunner"/>.
        /// </summary>
        /// <param name="trampoline">
        /// Optional existing trampoline. When null, a new <see cref="BasicTrampoline"/> is automatically created.
        /// </param>
        public BasicTrampolineRunner( BasicTrampoline? trampoline = null )
        {
            _reg = (trampoline ?? new BasicTrampoline()).AcquireOnce( this );
        }

        /// <summary>
        /// Initializes an execution context bound to an external memory.
        /// </summary>
        /// <param name="trampoline">Optional existing trampoline.</param>
        /// <param name="externalMemory">External memory.</param>
        /// </param>
        public BasicTrampolineRunner( BasicTrampoline? trampoline, IDictionary<object, object> externalMemory )
            : this( trampoline )
        {
            Throw.CheckNotNullArgument( externalMemory );
            _memory = externalMemory;
        }

        /// <summary>
        /// Gets whether this runner can run: <see cref="ExecuteAsync"/> or <see cref="ExecuteAllAsync"/>
        /// can be called only once.
        /// </summary>
        public bool CanExecute => _execFlag == 0;

        /// <summary>
        /// Get the current result.
        /// This is updated as soon as errors occurred and defaults to <see cref="TrampolineResult.TotalSuccess"/>
        /// until this runner is executed.
        /// </summary>
        public TrampolineResult Result => _result;

        /// <summary>
        /// Gets whether <see cref="ExecuteAsync"/> (true) or <see cref="ExecuteAllAsync"/> (false)
        /// has been called. This is null until one of these functions have been called.
        /// </summary>
        public bool? StopOnFirstError => _stopOnFirstError;

        /// <summary>
        /// Get the current error.
        /// This is updated as soon as errors occurred.
        /// A false return from a "gentle" action creates a "fake" <see cref="CKException"/>, multiple exceptions
        /// (when <see cref="ExecuteAllAsync"/> is used) are aggregated in an <see cref="AggregateException"/>.
        /// </summary>
        public Exception? Error => _error;

        void AddErrorAction( IActivityMonitor monitor, Exception? e )
        {
            _result |= TrampolineResult.Error;
            if( e == null )
            {
                monitor.Error( "An action returned false." );
                e = new CKException( "An action returned false." );
            }
            else
            {
                monitor.Error( e );
            }
            if( _error is AggregateException a )
            {
                _error = new AggregateException( a.InnerExceptions.Append( e ) );
            }
            else if( _error != null )
            {
                _error = new AggregateException( _error, e );
            }
            else
            {
                _error = e;
            }
        }

        /// <summary>
        /// Gets an optional memory that can be used to share state between actions.
        /// </summary>
        public IDictionary<object, object> Memory => _memory ?? (_memory = new Dictionary<object, object>());

        /// <summary>
        /// Gets the trampoline where Actions, error, success and/or finally handlers can be registered
        /// even when <see cref="ExecuteAsync"/> or <see cref="ExecuteAllAsync"/> is called.
        /// </summary>
        public BasicTrampoline Trampoline => _reg;

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
        /// <returns>The awaitable.</returns>
        public Task ExecuteAsync( IActivityMonitor monitor ) => DoExecuteAsync( monitor, false );

        /// <summary>
        /// Executes all the currently enlisted actions (optionally in reverse order) regardless of whether they fail or not
        /// and returns null on success.
        /// On error the single exception or an <see cref="AggregateException"/> with multiple exceptions is returned.
        /// <para>
        /// Note that during the execution, <see cref="StopOnFirstError"/> and the <see cref="Result"/> are available:
        /// an action can know that it is being executed in this mode and that one or more previous actions have failed.
        /// </para>
        /// </summary>
        /// <returns>The awaitable.</returns>
        public Task ExecuteAllAsync( IActivityMonitor monitor ) => DoExecuteAsync( monitor, true );

        async Task DoExecuteAsync( IActivityMonitor monitor, bool executeAll )
        {
            if( Interlocked.CompareExchange( ref _execFlag, 1, 0 ) != 0 )
            {
                Throw.InvalidOperationException( "This trampoline has already been executed or disposed." );
            }
            _stopOnFirstError = !executeAll;
            Debug.Assert( _result == TrampolineResult.TotalSuccess );

            var actions = _reg._actions;
            using( monitor.OpenInfo( $"{actions.Count} initial actions." ) )
            {
                int doneCount = 0;
                try
                {
                    int roundNumber = 0;
                    int roundCount;
                    while( (roundCount = actions.Count - doneCount) > 0 )
                    {
                        using( monitor.OpenTrace( $"Executing round n°{++roundNumber} with {roundCount} actions." ) )
                        {
                            while( --roundCount >= 0 )
                            {
                                if( executeAll )
                                {
                                    try
                                    {
                                        if( !await ExecuteInitialAction( actions[doneCount] ).ConfigureAwait( false ) )
                                        {
                                            AddErrorAction( monitor, null );
                                        }
                                    }
                                    catch( Exception e )
                                    {
                                        AddErrorAction( monitor, e );
                                    }
                                }
                                else if( !await ExecuteInitialAction( actions[doneCount] ).ConfigureAwait( false ) )
                                {
                                    AddErrorAction( monitor, null );
                                    break;
                                }
                                ++doneCount;
                            }
                        }
                    }
                    if( _result == TrampolineResult.TotalSuccess )
                    {
                        var onSuccess = _reg._onSuccess;
                        if( onSuccess != null )
                        {
                            using( monitor.OpenTrace( $"Calling {onSuccess.Count} success handlers." ) )
                            {
                                if( !await RaiseSuccessAsync( monitor, onSuccess ).ConfigureAwait( false ) ) _result |= TrampolineResult.HasSuccessException;
                            }
                        }
                    }
                    else
                    {
                        Debug.Assert( actions.Count == doneCount );
                        await ExecuteOnError( monitor, actions, doneCount ).ConfigureAwait( false );
                    }
                }
                catch( Exception ex )
                {
                    AddErrorAction( monitor, ex );
                    await ExecuteOnError( monitor, actions, doneCount ).ConfigureAwait( false );
                }
                finally
                {
                    if( _reg._onFinally != null )
                    {
                        using( monitor.OpenInfo( $"Calling {_reg._onFinally.Count} finally handlers." ) )
                        {
                            if( !await RaiseFinallyAsync( monitor, _reg._onFinally ).ConfigureAwait( false ) ) _result |= TrampolineResult.HasFinallyException;
                        }
                    }
                }
            }
        }

        async Task ExecuteOnError( IActivityMonitor monitor, List<object> actions, int doneCount )
        {
            _result |= TrampolineResult.Error;
            using( monitor.OpenError( $"Leaving {actions.Count - doneCount - 1} not executed actions." ) )
            {
                if( _reg._onError == null ) monitor.Trace( "There is no registered error handler." );
                else
                {
                    using( monitor.OpenInfo( $"Calling {_reg._onError.Count} error handlers." ) )
                    {
                        if( !await RaiseErrorAsync( monitor, _reg._onError ).ConfigureAwait( false ) ) _result |= TrampolineResult.HasErrorException;
                    }
                }
            }
        }

        static async ValueTask<bool> ExecuteInitialAction( object o )
        {
            switch( o )
            {
                case Func<bool> a: return a();
                case Func<Task<bool>> a: return await a().ConfigureAwait( false );
                case Func<ValueTask<bool>> a: return await a().ConfigureAwait( false );
                case Action a: a(); return true;
                case Func<ValueTask> a: await a().ConfigureAwait( false ); return true;
                default:
                    Debug.Assert( o is Func<Task> );
                    await ((Func<Task>)o)().ConfigureAwait( false );
                    return true;
            }
        }

        /// <summary>
        /// Executes the registered success handlers. This never throws.
        /// </summary>
        /// <param name="success">The success handlers.</param>
        /// <returns>False if a handler thrown.</returns>
        async Task<bool> RaiseSuccessAsync( IActivityMonitor monitor, List<Func<Task>> success )
        {
            _reg.SetHandlingSuccess();
            bool result = true;
            int doneCount = 0;
            int roundNumber = 0;
            int roundCount;
            while( (roundCount = success.Count - doneCount) > 0 )
            {
                using( monitor.OpenTrace( $"Executing Success handlers round n°{++roundNumber} with {roundCount} handlers." ) )
                {
                    for( int i = 0; i < roundCount; ++i )
                    {
                        try
                        {
                            await success[doneCount++].Invoke().ConfigureAwait( false );
                        }
                        catch( Exception ex )
                        {
                            result = false;
                            monitor.Error( $"While executing success handler. This is ignored.", ex );
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
        /// <returns>False if a handler thrown.</returns>
        async Task<bool> RaiseErrorAsync( IActivityMonitor monitor, List<Func<Task>> errors )
        {
            _reg.SetHandlingError();
            bool result = true;
            int doneCount = 0;
            int roundNumber = 0;
            int roundCount;
            while( (roundCount = errors.Count - doneCount) > 0 )
            {
                using( monitor.OpenTrace( $"Executing Error handling round n°{++roundNumber} with {roundCount} handlers." ) )
                {
                    for( int i = 0; i < roundCount; ++i )
                    {
                        try
                        {
                            await errors[doneCount++].Invoke().ConfigureAwait( false );
                        }
                        catch( Exception exError )
                        {
                            result = false;
                            monitor.Error( $"While handling error. This is ignored.", exError );
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
        async Task<bool> RaiseFinallyAsync( IActivityMonitor monitor, List<Func<Task>> final )
        {
            _reg.SetHandlingFinally();
            var result = true;
            int doneCount = 0;
            int roundNumber = 0;
            int roundCount;
            while( (roundCount = final.Count - doneCount) > 0 )
            {
                using( monitor.OpenTrace( $"Executing Final handlers round n°{++roundNumber} with {roundCount} handlers." ) )
                {
                    for( int i = 0; i < roundCount; ++i )
                    {
                        try
                        {
                            await final[doneCount++].Invoke().ConfigureAwait( false );
                        }
                        catch( Exception ex )
                        {
                            result = false;
                            monitor.Error( $"While executing final handler. This is ignored.", ex );
                        }
                    }
                }
            }
            _reg.ClearHandling();
            return result;
        }

    }


}
