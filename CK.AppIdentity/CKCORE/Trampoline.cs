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
    /// Trampoline actions on any <typeparamref name="T"/> registration.
    /// In practice, T is a <see cref="TrampolineRunner{T}"/> that handles the execution of the actions and
    /// acts as a context with a <see cref="TrampolineRunner{TSelf}.Monitor"/>, an optional <see cref="TrampolineRunner{TSelf}.Memory"/>
    /// and any other captured information that a specialized runner may expose.
    /// <para>
    /// Once a Trampoline has been provided to a runner, it cannot be provided to another one: the added actions and handlers are lost forever.
    /// This class is not thread.
    /// </para>
    /// </summary>
    public sealed class Trampoline<T>
    {
        // Actions are object. Pattern matching is used on them at execution time.
        internal readonly List<object> _actions;
        // Internal storage of success, error and finally are based on Task
        // with adapters.
        internal List<Func<T, Task>>? _onSuccess;
        internal List<Func<T, Exception?, Task>>? _onError;
        internal List<Func<T, Task>>? _onFinally;
        // A registrar can be owned by zero or one ExecutionContext, and only once.
        object? _owner;

        static readonly string _successStep = "Currently handling success.";
        static readonly string _errorStep = "Currently handling error.";
        static readonly string _finallyStep = "Currently handling finalization.";
        string? _handlingStep;

        internal Trampoline<T> AcquireOnce( object owner )
        {
            if( Interlocked.Exchange( ref _owner, owner ) == null ) return this;
            return Throw.InvalidOperationException<Trampoline<T>>();
        }

        /// <summary>
        /// Initializes a new empty trampoline.
        /// </summary>
        public Trampoline()
        {
            _actions = new List<object>();
        }

        /// <summary>
        /// Gets the number of actions that should be executed.
        /// </summary>
        public int ActionCount => _actions.Count;

        /// <summary>
        /// Adds a new action that only throws on error.
        /// <para>
        /// This can be called during the execution of an action but not by error or success handlers. 
        /// </para>
        /// </summary>
        /// <param name="action">The action to enqueue.</param>
        public void Add( Func<T, Task> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Func{T, Task})"/>
        public void Add( Func<T, ValueTask> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Func{T, Task})"/>
        public void Add( Action<T> action )
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
        public void Add( Func<T, Task<bool>> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Func{T, Task{bool}})"/>
        public void Add( Func<T, ValueTask<bool>> action )
        {
            GuardAdd( action == null );
            _actions.Add( action! );
        }

        /// <inheritdoc cref="Add(Func{T, Task{bool}})"/>
        public void Add( Func<T,bool> action )
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
                    case Func<T, bool>: 
                    case Func<T, Task<bool>>:
                    case Func<T, ValueTask<bool>>:
                    case Action<T>:
                    case Func<T, ValueTask>:
                    case Func<T, Task>:
                        _actions.Add( a );
                        break;
                    default:
                        Throw.ArgumentException( $"Expected Trampoline action function. Got a '{a}'.", nameof( actions ) );
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
        public void OnSuccess( Func<T, Task> successHandler )
        {
            GuardSuccess( successHandler == null );
            _onSuccess.Add( successHandler! );
        }

        /// <inheritdoc cref="OnSuccess(Func{T, Task})" />
        public void OnSuccess( Func<T, ValueTask> successHandler )
        {
            GuardSuccess( successHandler == null );
            _onSuccess.Add( c => successHandler!( c ).AsTask() );
        }

        /// <inheritdoc cref="OnSuccess(Func{T, Task})" />
        public void OnSuccess( Action<T> successHandler )
        {
            GuardSuccess( successHandler == null );
            _onSuccess.Add( c => { successHandler!( c ); return Task.CompletedTask; } );
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
        /// <remarks>
        /// The exception parameter is nullable since an initial action can fail by returning gentle false
        /// instead of throwing.
        /// </remarks>
        public void OnError( Func<T, Exception?, Task> errorHandler )
        {
            GuardError( errorHandler == null );
            _onError.Add( errorHandler! );
        }

        /// <inheritdoc cref="OnError(Func{T, Exception?, Task})" />
        public void OnError( Func<T, Exception?, ValueTask> errorHandler )
        {
            GuardError( errorHandler == null );
            _onError.Add( ( c, ex ) => errorHandler!( c, ex ).AsTask() );
        }

        /// <inheritdoc cref="OnError(Func{T, Exception?, Task})" />
        public void OnError( Action<T, Exception?> errorHandler )
        {
            GuardError( errorHandler == null );
            _onError.Add( ( c, ex ) => { errorHandler!( c, ex ); return Task.CompletedTask; } );
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
        public void Finally( Func<T, Task> finallyHandler )
        {
            GuardFinally( finallyHandler == null );
            _onFinally.Add( finallyHandler! );
        }

        /// <inheritdoc cref="Finally(Func{T, Task})" />
        public void Finally( Func<T, ValueTask> finalHandler )
        {
            GuardFinally( finalHandler == null );
            _onFinally.Add( c => finalHandler!( c ).AsTask() );
        }

        /// <inheritdoc cref="Finally(Func{T, Task})" />
        public void Finally( Action<T> finalHandler )
        {
            GuardFinally( finalHandler == null );
            _onFinally.Add( c => { finalHandler!( c ); return Task.CompletedTask; } );
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
            _onSuccess ??= new List<Func<T, Task>>();
        }

        [MemberNotNull( nameof( _onError ) )]
        void GuardError( bool nullArg )
        {
            if( nullArg ) Throw.ArgumentNullException( "errorHandler" );
            if( ReferenceEquals( _handlingStep, _successStep ) || ReferenceEquals( _handlingStep, _finallyStep ) )
            {
                Throw.InvalidOperationException( _handlingStep );
            }
            _onError ??= new List<Func<T, Exception?, Task>>();
        }

        [MemberNotNull( nameof( _onFinally ) )]
        void GuardFinally( bool nullArg )
        {
            if( nullArg ) Throw.ArgumentNullException( "finallyHandler" );
            _onFinally ??= new List<Func<T, Task>>();
        }
    }
}
