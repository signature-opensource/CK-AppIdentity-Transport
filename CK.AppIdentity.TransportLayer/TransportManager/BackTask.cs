using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
            public BackTask? First;
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

            public List( TransportManager transportManager )
            {
                _transportManager = transportManager;
                _queue = new PriorityQueue<BackTask, int>();
            }

            public int Count => _queue.Count;

            public void Destroy( IActivityMonitor monitor )
            {
                while( _queue.Count > 0 )
                {
                    _queue.Dequeue().OnDestroy( monitor, _transportManager );
                }
            }

            public void OnHeartBeat( IActivityMonitor monitor )
            {
                var t = _queue.Peek();
                while( t._checkTick <= _tick )
                {
                    t.Check( monitor, _transportManager );
                    if( t._checkTick > _tick )
                    {
                        _queue.Enqueue( t, t._checkTick );
                    }
                    else
                    {
                        t.Reset();
                        t._nextFree = t._head.First;
                        t._head.First = t;
                    }
                }
                ++_tick;
            }

            /// <summary>
            /// Configures a BackTask to run in the background.
            /// </summary>
            /// <typeparam name="T">The type of the BackTask.</typeparam>
            /// <param name="head">The back task head for <typeparamref name="T"/>.</param>
            /// <param name="configure">The configuration action.</param>
            /// <param name="ticks">Must be positive.</param>
            public void Add<T>( Head head, Action<T> configure, int ticks ) where T : BackTask, new()
            {
                Debug.Assert( ticks > 0 );
                T t;
                if( head.First != null )
                {
                    t = (T)head.First;
                    Debug.Assert( t._head == head );
                    head.First = t._nextFree;
                }
                else
                {
#if DEBUG
                    Throw.CheckArgument( head.Type == typeof(T) );
#endif
                    t = new() { _head = head };
                }
                t._checkTick = _tick + 1;
                configure( t );
                _queue.Enqueue( t, t._checkTick );
            }
        }

        /// <summary>
        /// Can be called by <see cref="Check"/> if this task must be retried.
        /// </summary>
        /// <param name="ticks">Must be positive.</param>
        protected void Retry( int ticks )
        {
            Debug.Assert( ticks > 0 );
            _checkTick += ticks;
        }

        /// <summary>
        /// Gets the current tick.
        /// </summary>
        protected int CurrentTick => _checkTick;

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
