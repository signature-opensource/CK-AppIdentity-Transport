using CK.Core;
using CK.PerfectEvent;
using Newtonsoft.Json.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{

    sealed class Collector<TEmitter, T> : ICollector<TEmitter, T> where T : class
    {
        Node? _first;
        Node? _last;
        PerfectEventSender<TEmitter, T> _added;
        int _count;

        internal Collector()
        {
            _added = new PerfectEventSender<TEmitter, T>();
        }

        /// <summary>
        /// Non thread safe but the collection is safe: the enumerator
        /// traverse the linked list that can only grow at the end.
        /// </summary>
        internal void Add( T v )
        {
            var n = new Node( v );
            if( _first == null )
            {
                _first = n;
                _last = n;
            }
            else
            {
                Debug.Assert( _last != null );
                _last.Next = n;
            }
            ++_count;
        }

        internal Task RaiseAdded( IActivityMonitor monitor, TEmitter c, T v ) => _added.SafeRaiseAsync( monitor, c, v );

        public PerfectEvent<TEmitter, T> Added => _added.PerfectEvent;

        public int Count => _count;

        sealed class Node
        {
            public readonly T Value;
            public Node? Next;

            public Node( T v )
            {
                Value = v;
            }
        }

        public struct Enumerator : IEnumerator<T>
        {
            Node? _current;

            internal Enumerator( Collector<TEmitter, T> s )
            {
                _current = s._first;
            }

            public T Current
            {
                get
                {
                    Throw.CheckState( _current != null );
                    return _current.Value;
                }
            }

            object IEnumerator.Current => Current;

            public void Dispose()
            {
            }

            public bool MoveNext()
            {
                _current = _current?.Next;
                return _current != null;
            }

            public void Reset() => Throw.NotSupportedException();
        }

        public Enumerator GetEnumerator() => new Enumerator( this );

        IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
