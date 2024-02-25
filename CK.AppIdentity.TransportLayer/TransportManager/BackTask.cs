using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Crappy implementation of reusable background and dangerous tasks such
    /// as accepting an incoming connection.
    /// The neste BackTaskList holds tasks that are executing and have a high risk of failure or timeout,
    /// either because they handle the start of unknown parties or the byebye message of a condemned
    /// transport.
    /// Instead of allocating a CTS (with a TimerQueue) for them, the TransportManager's heart beat checks them
    /// periodically. If they are pending (blocked, may be by a malicious remote), we destroy (Dispose) the
    /// underlying resource that frees the blocked task.
    /// </summary>
    abstract class BackTask
    {
        [AllowNull]
        Head _head;
        BackTask? _nextFree;
        int _checkTick;

        /// <summary>
        /// Head of the free list for a type of BackTask.
        /// Type checking is done in DEBUG only.
        /// </summary>
        public sealed class Head
        {
            public BackTask? FreeHead;
#if DEBUG
            public readonly Type Type;
            Head( Type tTask ) => Type = tTask;
            public static Head Create<T>() where T : BackTask => new Head( typeof(T) );
#else
            public static Head Create<T>() => new Head();
#endif
        }

        /// <summary>
        /// The BackTaskList is nested so that it has access to BackTask private fields.
        /// </summary>
        public sealed class List
        {
            readonly TransportManager _transportManager;
            readonly PriorityQueue<BackTask, int> _queue;
            int _tick;
            int _totalCount;

            public List( TransportManager transportManager )
            {
                _transportManager = transportManager;
                _queue = new PriorityQueue<BackTask, int>();
            }

            public int AliveCount => _queue.Count;
            public int TotalCount => _totalCount;

            public void Destroy( IActivityMonitor monitor )
            {
                using( monitor.OpenInfo( $"Destroying {_queue.Count} back tasks." ) )
                {
                    while( _queue.Count > 0 )
                    {
                        _queue.Dequeue().OnDestroy( monitor, _transportManager );
                    }
                }
            }

            public (int,int) OnHeartBeat( IActivityMonitor monitor )
            {
                Throw.DebugAssert( _queue.Count > 0 );
                int handled = 0;
                int done = 0;
                // Preincrement the tick: previous initialisation or check
                // are bound to the previous tick.
                ++_tick;
                var t = _queue.Peek();
                while( t._checkTick <= _tick )
                {
                    ++handled;
                    t._checkTick = _tick;
                    t.Check( monitor, _transportManager );
                    Throw.DebugAssert( t._checkTick >= _tick );
                    if( t._checkTick > _tick )
                    {
                        _queue.Enqueue( t, t._checkTick );
                    }
                    else
                    {
                        ++done;
                        Reset( monitor, t );
                    }
                    _queue.Dequeue();
                    if( _queue.Count == 0 ) break;
                    t = _queue.Peek();
                }
                return (handled, done);
            }

            static void Reset( IActivityMonitor monitor, BackTask t )
            {
                monitor.Debug( $"Reseting backTask {t.GetType().Name} #{t.GetHashCode()}." );
                t.Reset();
                t._nextFree = t._head.FreeHead;
                t._head.FreeHead = t;
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
            public void Initialize<T>( IActivityMonitor monitor, Head head, Action<T> onInitialize ) where T : BackTask, new()
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
                    t = new() { _head = head };
                    monitor.Trace( $"Created new backTask: {t.GetType().Name} #{t.GetHashCode()}." );
                    ++_totalCount;
                }
                Throw.DebugAssert( t._head == head );
                t._checkTick = _tick;
                onInitialize( t );
                Throw.DebugAssert( t._checkTick >= _tick );
                if( t._checkTick == _tick )
                {
                    Reset( monitor, t );
                }
                else
                {
                    monitor.Debug( $"Backtask {t.GetType().Name} #{t.GetHashCode()} will be checked in {t._checkTick - _tick} heartbeats." );
                    _queue.Enqueue( t, t._checkTick );
                }
            }
        }

        /// <summary>
        /// Initially called by the <see cref="BackTask.List.Initialize{T}(Head, Action{T})"/> configuration action
        /// and then by <see cref="Check"/> when this back task must continue to be checked.
        /// </summary>
        /// <param name="delay">Must be positive.</param>
        protected void Retry( int delay )
        {
            Throw.DebugAssert( delay > 0 );
            _checkTick += delay;
        }

        /// <summary>
        /// Checks whatever it has to check. Can call <see cref="Retry(int)"/> if needed.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="transportManager">The transport manager.</param>
        public abstract void Check( IActivityMonitor monitor, TransportManager transportManager );

        /// <summary>
        /// Must reset all the fields of this task. Called before releasing this task to its pool.
        /// </summary>
        public abstract void Reset();

        /// <summary>
        /// Called when the transport manager is destroyed.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="transportManager">The dying transport manager.</param>
        public abstract void OnDestroy( IActivityMonitor monitor, TransportManager transportManager );
    }
}
