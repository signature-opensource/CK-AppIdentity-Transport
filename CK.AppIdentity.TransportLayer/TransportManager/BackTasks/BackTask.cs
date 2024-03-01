using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Simple implementation of reusable background and dangerous tasks such
    /// as accepting an incoming connection.
    /// The nested BackTaskManager holds non generic tasks that are executing and have a high risk of
    /// failure or timeout.
    /// <para>
    /// Instead of allocating a CTS (with a TimerQueue) for them, the TransportManager's heart beat checks them
    /// periodically. If they are pending (blocked, may be by a malicious remote), we destroy (Dispose) the
    /// underlying resource that frees the blocked task.
    /// </para>
    /// </summary>
    abstract class BackTask<THost>
    {
        /// <summary>
        /// The maximum check delay is one year.
        /// </summary>
        public const int MaxCheckDelay = 365 * 24 * 60 * 60;

        [AllowNull] Head _head;
        [AllowNull] BackTaskManager _manager;
        BackTask<THost>? _nextFree;
        int _nextCheckDelay;

        /// <summary>
        /// Head of the free list for a type of BackTask.
        /// Type checking is done in DEBUG only.
        /// </summary>
        public sealed class Head
        {
            public BackTask<THost>? FreeHead;
#if DEBUG
            public readonly Type Type;
            Head( Type tTask ) => Type = tTask;
            public static Head Create<T>() where T : BackTask<THost> => new Head( typeof(T) );
#else
            public static Head Create<T>() => new Head();
#endif
        }

        /// <summary>
        /// The BackTaskManager is nested so that it has access to BackTask private fields.
        /// </summary>
        public sealed class BackTaskManager : IBackTaskManager<THost>
        {
            readonly THost _host;
            readonly PriorityQueue<BackTask<THost>, int> _queue;
            int _tick;
            int _totalCount;

            public BackTaskManager( THost transportManager )
            {
                _host = transportManager;
                _queue = new PriorityQueue<BackTask<THost>, int>();
            }

            public int AliveCount => _queue.Count;

            public int TotalCount => _totalCount;

            public int TotalTicks => _tick;

            public void Destroy( IActivityMonitor monitor )
            {
                using( monitor.OpenInfo( $"Destroying {_queue.Count} back tasks." ) )
                {
                    while( _queue.Count > 0 )
                    {
                        _queue.Dequeue().OnDestroy( monitor );
                    }
                }
            }

            public (int Handled, int Reset) OnHeartBeat( IActivityMonitor monitor )
            {
                Throw.DebugAssert( _queue.Count > 0 );
                int handled = 0;
                int reset = 0;
                // Preincrement the tick: previous initialisation or check
                // are bound to the previous tick.
                ++_tick;
                while( _queue.TryPeek( out var t, out var tTicks ) && tTicks <= _tick )
                {
                    ++handled;
                    var previous = t._nextCheckDelay;
                    t._nextCheckDelay = 0;
                    t.Check( monitor, previous );
                    if( t._nextCheckDelay > 0 )
                    {
                        _queue.Enqueue( t,  _tick + t._nextCheckDelay );
                    }
                    else
                    {
                        ++reset;
                        Reset( monitor, t );
                    }
                    _queue.Dequeue();
                }
                return (handled, reset);
            }

            /// <summary>
            /// Configures a BackTask to run in the background.
            /// <para>
            /// The <paramref name="onInitialize"/> action must call <see cref="BackTask.Retry(int)"/> (with a positive delay)
            /// otherwise the back task will be <see cref="BackTask.Reset"/> and sent back to its pool.
            /// </para>
            /// </summary>
            /// <typeparam name="T">The type of the BackTask.</typeparam>
            /// <param name="head">The back task head for <typeparamref name="T"/>.</param>
            /// <param name="onInitialize">The configuration action.</param>
            public void Initialize<T>( IActivityMonitor monitor, Head head, Action<T> onInitialize ) where T : BackTask<THost>, new()
            {
                var t = (T?)head.FreeHead;
                if( t != null )
                {
                    head.FreeHead = t._nextFree;
                    monitor.Debug( $"Reusing backTask: {t.GetType().Name} #{t.GetHashCode()}." );
                }
                else
                {
#if DEBUG
                    Throw.CheckArgument( head.Type == typeof(T) );
#endif
                    t = new() { _head = head, _manager = this };
                    monitor.Trace( $"Created new backTask: {t.GetType().Name} #{t.GetHashCode()}." );
                    ++_totalCount;
                }
                Throw.DebugAssert( t._head == head );
                t._nextCheckDelay = 0;
                onInitialize( t );
                if( t._nextCheckDelay == 0 )
                {
                    Reset( monitor, t );
                }
                else
                {
                    _queue.Enqueue( t, _tick + t._nextCheckDelay );
                }
            }

            THost IBackTaskManager<THost>.Host => _host;

            static void Reset( IActivityMonitor monitor, BackTask<THost> t )
            {
                monitor.Debug( $"Reseting backTask {t.GetType().Name} #{t.GetHashCode()}." );
                t.Reset();
                t._nextFree = t._head.FreeHead;
                t._head.FreeHead = t;
            }

        }

        /// <summary>
        /// Gets or sets the next check delay.
        /// Must be let to 0 (the initial default before calling <see cref="Check"/>).
        /// Must not be greater than <see cref="MaxCheckDelay"/>.
        /// </summary>
        protected int NextCheckDelay
        {
            get => _nextCheckDelay;
            set
            {
                Throw.CheckArgument( value >= 0 && value <= MaxCheckDelay );
                _nextCheckDelay = value;
            }
        }

        /// <summary>
        /// Gets the back task manager.
        /// </summary>
        protected IBackTaskManager<THost> TaskManager => _manager;

        /// <summary>
        /// Checks whatever it has to check. Must set <see cref="NextCheckDelay"/> if needed check must be called again.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="previousCheckDelay">
        /// The previous <see cref="NextCheckDelay"/> value. Can be used to dynaically adjust the check rate.
        /// </param>
        public abstract void Check( IActivityMonitor monitor, int previousCheckDelay );

        /// <summary>
        /// Called before releasing this task to its pool (<see cref="NextCheckDelay"/> has been let to 0 by the initializer
        /// function or by <see cref="Check"/>.
        /// Must reset all the fields of this task. 
        /// </summary>
        public abstract void Reset();

        /// <summary>
        /// Called when the transport manager is destroyed.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        public abstract void OnDestroy( IActivityMonitor monitor );
    }
}
