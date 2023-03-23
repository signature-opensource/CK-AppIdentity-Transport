using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.SymbolStore;
using System.Threading;
using System.Threading.Tasks;

namespace CK.Core
{
    /// <summary>
    /// Basic trampoline.
    /// <para>
    /// Once a Trampoline has been provided to a runner, it cannot be provided to another one: the added actions and handlers are lost forever.
    /// This class is not thread.
    /// </para>
    /// </summary>
    public sealed class BasicTrampoline
    {
        // Actions are object. Pattern matching is used on them at execution time.
        internal readonly List<object> _actions;
        // Internal storage of success, error and finally are based on Task
        // with adapters.
        internal List<Func<Task>>? _onSuccess;
        internal List<Func<Task>>? _onError;
        internal List<Func<Task>>? _onFinally;
        // A registrar can be owned by zero or one ExecutionContext, and only once.
        object? _owner;

        static readonly string _successStep = "Currently handling success.";
        static readonly string _errorStep = "Currently handling error.";
        static readonly string _finallyStep = "Currently handling finalization.";
        string? _handlingStep;

        internal BasicTrampoline AcquireOnce( object owner )
        {
            if( Interlocked.Exchange( ref _owner, owner ) == null ) return this;
            return Throw.InvalidOperationException<BasicTrampoline>();
        }

        /// <summary>
        /// Initializes a new empty trampoline.
        /// </summary>
        public BasicTrampoline()
        {
            _actions = new List<object>();
        }

        /// <summary>
        /// Gets the number of actions that have been registered.
        /// </summary>
        public int ActionCount => _actions.Count;

        /// <summary>
        /// Adds a new action that only throws on error.
        /// <para>
        /// This can be called during the execution of an action but not by error or success handlers. 
        /// </para>
        /// </summary>
        /// <param name="action">The action to enqueue.</param>
        public void Add( Action action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Action)"/>
        public void Add( Func<Task> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Action)"/>
        public void Add( Func<ValueTask> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <summary>
        /// Adds a new action that can return false on error (or throw an exception).
        /// <para>
        /// This can be called during the execution of an action but not by error or success handlers. 
        /// </para>
        /// </summary>
        /// <param name="action">The action to enqueue.</param>
        public void Add( Func<bool> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Func{bool})"/>
        public void Add( Func<Task<bool>> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Func{bool})"/>
        public void Add( Func<ValueTask<bool>> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <summary>
        /// Adds a list of actions (that must be valid actions otherwise an <see cref="ArgumentException"/> is thrown).
        /// This can be called during the execution of an action but not by error or success handlers. 
        /// </summary>
        /// <param name="actions">The actions to enqueue.</param>
        public void AddRange( IEnumerable<object> actions )
        {
            GuardAdd( actions == null );
            foreach( var a in actions! )
            {
                switch( a )
                {
                    case Action:
                    case Func<bool>:
                    case Func<Task<bool>>:
                    case Func<ValueTask<bool>>:
                    case Func<ValueTask>:
                    case Func<Task>:
                        _actions.Add( a );
                        break;
                    default:
                        Throw.ArgumentException( $"Expected BasicTrampoline action. Got a '{a}'.", nameof( actions ) );
                        break;
                }
            }
        }

        /// <summary>
        /// Registers a new success handler.
        /// <para>
        /// This will be called once all initial actions have been executed without errors.
        /// Any exception thrown by this handler will be logged and ignored: a success handler
        /// should not fail.
        /// </para>
        /// <para>
        /// A success handler is not allowed to register any new action or error handler but it can
        /// register another success or finally handler if needed.
        /// </para>
        /// </summary>
        /// <param name="successHandler">The success handler to register.</param>
        public void OnSuccess( Action successHandler )
        {
            GuardSuccess( successHandler == null );
            _onSuccess.Add( () => { successHandler!(); return Task.CompletedTask; } );
        }

        /// <inheritdoc cref="OnSuccess(Action)"/>
        public void OnSuccess( Func<Task> successHandler )
        {
            GuardSuccess( successHandler == null );
            _onSuccess.Add( successHandler! );
        }

        /// <inheritdoc cref="OnSuccess(Action)"/>
        public void OnSuccess( Func<ValueTask> successHandler )
        {
            GuardSuccess( successHandler == null );
            _onSuccess.Add( () => successHandler!().AsTask() );
        }

        /// <summary>
        /// Registers a new error handler.
        /// <para>
        /// This will be called if an action throws an exception.
        /// Any exception thrown by this handler will be logged and ignored: an error handler should not fail.
        /// <para>
        /// </para>
        /// An error handler is not allowed to register any
        /// new action or success handler but it can register another error or finally handler if needed.
        /// </para>
        /// </summary>
        /// <param name="errorHandler">The error handler to register.</param>
        public void OnError( Action errorHandler )
        {
            GuardError( errorHandler == null );
            _onError.Add( () => { errorHandler!(); return Task.CompletedTask; } );
        }

        /// <inheritdoc cref="OnError(Action)"/>
        public void OnError( Func<Task> errorHandler )
        {
            GuardError( errorHandler == null );
            _onError.Add( errorHandler! );
        }

        /// <inheritdoc cref="OnError(Action)"/>
        public void OnError( Func<ValueTask> errorHandler )
        {
            GuardError( errorHandler == null );
            _onError.Add( () => errorHandler!().AsTask() );
        }


        /// <summary>
        /// Registers a new finally handler.
        /// <para>
        /// This will be called after success or error handlers.
        /// Any exception thrown by this handler will be logged and ignored: a finally handler should not fail.
        /// </para>
        /// <para>
        /// A finally handler is not allowed to register any new action, success or error handler but it can register
        /// another finally handler if needed.
        /// </para>
        /// </summary>
        /// <param name="finallyHandler">The finally handler to register.</param>
        public void Finally( Action finalHandler )
        {
            GuardFinally( finalHandler == null );
            _onFinally.Add( () => { finalHandler!(); return Task.CompletedTask; } );
        }

        /// <inheritdoc cref="Finally(Action)"/>
        public void Finally( Func<Task> finallyHandler )
        {
            GuardFinally( finallyHandler == null );
            _onFinally.Add( finallyHandler! );
        }

        /// <inheritdoc cref="Finally(Action)"/>
        public void Finally( Func<ValueTask> finalHandler )
        {
            GuardFinally( finalHandler == null );
            _onFinally.Add( () => finalHandler!().AsTask() );
        }

        internal void SetHandlingError() => _handlingStep = _errorStep;
        internal void SetHandlingSuccess() => _handlingStep = _successStep;
        internal void SetHandlingFinally() => _handlingStep = _finallyStep;
        internal void ClearHandling() => _handlingStep = null;

        void GuardAdd( bool nullArg )
        {
            if( nullArg ) Throw.ArgumentNullException( "action" );
            if( _handlingStep != null )
            {
                Throw.InvalidOperationException( _handlingStep );
            }
        }

        [MemberNotNull( nameof( _onSuccess ) )]
        void GuardSuccess( bool nullArg )
        {
            if( nullArg ) Throw.ArgumentNullException( "successHandler" );
            if( ReferenceEquals( _handlingStep, _errorStep ) || ReferenceEquals( _handlingStep, _finallyStep ) )
            {
                Throw.InvalidOperationException( _handlingStep );
            }
            _onSuccess ??= new List<Func<Task>>();
        }

        [MemberNotNull( nameof( _onError ) )]
        void GuardError( bool nullArg )
        {
            if( nullArg ) Throw.ArgumentNullException( "errorHandler" );
            if( ReferenceEquals( _handlingStep, _successStep ) || ReferenceEquals( _handlingStep, _finallyStep ) )
            {
                Throw.InvalidOperationException( _handlingStep );
            }
            _onError ??= new List<Func<Task>>();
        }

        [MemberNotNull( nameof( _onFinally ) )]
        void GuardFinally( bool nullArg )
        {
            if( nullArg ) Throw.ArgumentNullException( "finallyHandler" );
            _onFinally ??= new List<Func<Task>>();
        }
    }
}
