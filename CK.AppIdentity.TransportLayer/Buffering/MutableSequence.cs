using System.Buffers;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Reusable <see cref="ReadOnlySequence{T}"/>.
    /// <see cref="Clear"/> must be called to free its resources and use it again.
    /// </summary>
    public sealed class MutableSequence<T> : IBufferWriter<T>, IDisposable where T : struct
    {
        /// <summary>
        /// Default and initial value of <see cref="MinimumBufferSize"/>.
        /// </summary>
        public const int DefaultMinimumBufferSize = 16;

        Segment? _head;
        Segment? _tail;
        Memory<T> _tailMemory;
        int _bytesBuffered;

        // Minimum buffer size.
        int _minimumBufferSize;
        // Maximal buffer size from the optional pool or -1 if the ArrayPool<T>.Shared is always used.
        readonly int _maxPooledBufferSize;
        // Optional pool (from Options). When null, _maxPooledBufferSize is -1 and
        // the ArrayPool<T>.Shared is always used.
        // When a pool exists, the ArrayPool<T>.Shared is used only when the
        // requested size is greater than _maxPooledBufferSize (that is MemoryPool<T>.MaxBufferSize).
        readonly MemoryPool<T>? _pool;

        // Local segment pool: the SequenceSegment.Next is also used to
        // chain the segments in the free list.
        int _freeSegmentMaxSize;
        Segment? _freeSegmentHead;
        int _freeSegmentSize;

        /// <summary>
        /// Initializes a new <see cref="MutableSequence{T}"/>.
        /// This must be disposed once done with it.
        /// </summary>
        /// <param name="pool">Pool to use instead of <see cref="ArrayPool{T}.Shared"/>.</param>
        public MutableSequence( MemoryPool<T>? pool = null )
        {
            _minimumBufferSize = 16;
            _pool = pool == MemoryPool<T>.Shared ? null : pool;
            _maxPooledBufferSize = _pool?.MaxBufferSize ?? -1;
            _freeSegmentMaxSize = 128;
        }

        /// <summary>
        /// Dispose this buffer.
        /// This simply call <see cref="Clear"/>: a disposed buffer can actually be reused.
        /// </summary>
        public void Dispose()
        {
            Clear();
        }

        /// <summary>
        /// Gets or sets the minimum length for any array allocated as a segment in the sequence.
        /// The minimum and default value is <see cref="DefaultMinimumBufferSize"/> and <see cref="Clear"/>
        /// restores this default: this value must be configured if needed each time this MutableSequence is reused.
        /// <para>
        /// <see cref="GetSpan(int)"/> or <see cref="GetMemory(int)"/> return memory from the current sequence
        /// if possible, but if new memory must be allocated, the <c>sizeHint</c> argument dictates
        /// the (minimal) length of the new array. When the caller uses very small values (just enough for its immediate need)
        /// but the high level scenario can predict that a large amount of memory will be ultimately required,
        /// it can be advisable to set this property to a value such that just a few larger arrays are allocated
        /// instead of many small ones.
        /// </para>
        /// <para>
        /// The <see cref="MemoryPool{T}"/> in use may itself have a minimum array length as well,
        /// in which case the higher of the two minimums dictates the minimum array size that will be allocated.
        /// </para>
        /// </summary>
        public int MinimumBufferSize
        {
            get => _minimumBufferSize;
            set
            {
                Throw.CheckOutOfRangeArgument( value >= DefaultMinimumBufferSize );
                _minimumBufferSize = value;
            }
        }

        /// <summary>
        /// Gets or sets the maximum number of internal <see cref="ReadOnlySequenceSegment{T}"/> implementations
        /// that are cached and reused by this mutable sequence instead of being newed and GCed.
        /// <para>
        /// Defaults to 128. Change to this value is not erased by <see cref="Clear"/> since it drives
        /// the behavior across reuse of the same MutableSequence.
        /// </para>
        /// </summary>
        public int LocalSegmentCacheSize
        {
            get => _freeSegmentMaxSize;
            set
            {
                Throw.CheckOutOfRangeArgument( value >= 0 );
                _freeSegmentMaxSize = value;
            }
        }


        /// <summary>
        /// Gets the free length available in the current sequence.
        /// </summary>
        public int CurrentlyAvailableLength => _tailMemory.Length;

        /// <inheritdoc />
        public void Advance( int count )
        {
            Throw.CheckArgument( (uint)count <= (uint)_tailMemory.Length );
            _bytesBuffered += count;
            _tail!.Length += count;
            _tailMemory = _tailMemory.Slice( count );
        }

        /// <inheritdoc />
        public Memory<T> GetMemory( int sizeHint = 0 )
        {
            Throw.CheckOutOfRangeArgument( sizeHint >= 0 );
            AllocateMemory( sizeHint );
            return _tailMemory;
        }

        /// <inheritdoc />
        public Span<T> GetSpan( int sizeHint = 0 )
        {
            Throw.CheckOutOfRangeArgument( sizeHint >= 0 );
            AllocateMemory( sizeHint );
            return _tailMemory.Span;
        }

        /// <summary>
        /// Gets the count of items in this buffer.
        /// </summary>
        public long Length => _bytesBuffered;

        /// <summary>
        /// Gets a <see cref="ReadOnlySequence{T}"/> of this buffer content.
        /// By using <see cref="System.Runtime.InteropServices.MemoryMarshal.AsMemory{T}(ReadOnlyMemory{T})"/>,
        /// each segment may be modified before publishing this sequence.
        /// </summary>
        /// <param name="startIndex">Optional start index in the buffer.</param>
        /// <returns>This sequence content.</returns>
        public ReadOnlySequence<T> GetReadOnlySequence( int startIndex = 0 ) => _head == null
                                                                                ? ReadOnlySequence<T>.Empty
                                                                                : new ReadOnlySequence<T>( _head, startIndex, _tail!, _tail!.Length );

        /// <summary>
        /// Clears this buffer. It can be reused.
        /// </summary>
        public void Clear()
        {
            int count = 0;
            _minimumBufferSize = DefaultMinimumBufferSize;
            Segment? segment = _head;
            while( segment != null )
            {
                ++count;
                segment.Free();
                Debug.Assert( segment.Next != null || _tail == segment );
                segment = segment.Next;
            }
            if( count > 0 )
            {
                Debug.Assert( _head != null && _tail != null );
                if( count == 1 ) ReleaseSegment( _head );
                else ReleaseSegments( _head, _tail, count );
                _head = null;
                _tail = null;
                _tailMemory = default;
                _bytesBuffered = 0;
            }
        }

        void AllocateMemory( int sizeHint )
        {
            if( _head == null )
            {
                // We need to allocate memory to write since nobody has written before.
                Segment newSegment = AllocateSegment( 0, sizeHint );
                _tailMemory = newSegment.AvailableMemory;
                _head = _tail = newSegment;
            }
            else
            {
                Debug.Assert( _tail != null );
                int bytesLeftInBuffer = _tailMemory.Length;

                // sizeHint is 0 by default ("Give me whatever you have").
                // In such case if there is no more room at all and we must allocate.
                if( bytesLeftInBuffer == 0 || bytesLeftInBuffer < sizeHint )
                {
                    Segment newSegment = AllocateSegment( _tail.RunningIndex + _tail.Length, sizeHint );
                    _tailMemory = newSegment.AvailableMemory;
                    _tail.Next = newSegment;
                    _tail = newSegment;
                }
            }
        }

        Segment AllocateSegment( long runningIndex, int sizeHint )
        {
            Debug.Assert( sizeHint >= 0 );
            Segment? newSegment = _freeSegmentHead;
            if( newSegment != null )
            {
                _freeSegmentHead = newSegment.Next;
                newSegment.Next = null;
                --_freeSegmentSize;
            }
            else
            {
                newSegment = new Segment();
            }
            int maxSize = _maxPooledBufferSize;
            if( sizeHint <= maxSize )
            {
                // Use the specified pool as it fits. Specified pool is not null as maxSize == -1 if _pool is null.
                newSegment.Initialize( runningIndex, _pool!.Rent( GetSegmentSize( sizeHint, maxSize ) ) );
            }
            else
            {
                // Use the array pool.
                int sizeToRequest = GetSegmentSize( sizeHint );
                newSegment.Initialize( runningIndex, ArrayPool<T>.Shared.Rent( sizeToRequest ) );
            }
            return newSegment;
        }

        int GetSegmentSize( int sizeHint, int maxBufferSize = int.MaxValue )
        {
            // First we need to handle case where hint is smaller than minimum segment size.
            sizeHint = Math.Max( _minimumBufferSize, sizeHint );
            // After that adjust it to fit into pools max buffer size.
            var adjustedToMaximumSize = Math.Min( maxBufferSize, sizeHint );
            return adjustedToMaximumSize;
        }

        void ReleaseSegment( Segment segment )
        {
            if( _freeSegmentSize < _freeSegmentMaxSize )
            {
                segment.Next = _freeSegmentHead;
                _freeSegmentHead = segment;
                ++_freeSegmentSize;
            }
        }

        void ReleaseSegments( Segment head, Segment tail, int count )
        {
            int newPoolSize = _freeSegmentSize + count;
            if( newPoolSize <= _freeSegmentMaxSize )
            {
                tail.Next = _freeSegmentHead;
                _freeSegmentHead = head;
                _freeSegmentSize = newPoolSize;
            }
            else
            {
                ReleaseSegmentsSlow( head );
            }
        }

        void ReleaseSegmentsSlow( Segment head )
        {
            var keep = _freeSegmentMaxSize - _freeSegmentSize;
            for( int i = 0; i < keep; ++i )
            {
                var n = head.Next;
                Debug.Assert( n != null );
                head.Next = _freeSegmentHead;
                _freeSegmentHead = head;
                head = n;
            }
            _freeSegmentSize = _freeSegmentMaxSize;
        }

        sealed class Segment : ReadOnlySequenceSegment<T>
        {
            IMemoryOwner<T>? _memoryOwner;
            T[]? _array;
            Memory<T> _availableMemory;

            /// <summary>
            /// Gets or sets the actual length of this buffer: this is
            /// the <see cref="ReadOnlySequenceSegment{T}.Memory"/>'s length.
            /// When setting, it must not be greater than <see cref="AvailableMemory"/>'s length.
            /// </summary>
            public int Length
            {
                [MethodImpl( MethodImplOptions.AggressiveInlining )]
                get => Memory.Length;
                [MethodImpl( MethodImplOptions.AggressiveInlining )]
                set
                {
                    Debug.Assert( value <= AvailableMemory.Length );
                    Memory = AvailableMemory.Slice( 0, value );
                }
            }

            /// <summary>
            /// Masked to be a Segment rather than ReadOnlySequenceSegment of bytes.
            /// </summary>
            public new Segment? Next
            {
                get => Unsafe.As<Segment?>( base.Next );
                set => base.Next = value;
            }

            /// <summary>
            /// Initializes this buffer with a memory from a pool.
            /// </summary>
            /// <param name="runningIndex">The running index to initialize.</param>
            /// <param name="memoryOwner">This buffer memory's owner.</param>
            public void Initialize( long runningIndex, IMemoryOwner<T> memoryOwner )
            {
                RunningIndex = runningIndex;
                _memoryOwner = memoryOwner;
                _availableMemory = memoryOwner.Memory;
            }

            /// <summary>
            /// Initializes this buffer with an array from the shared pool.
            /// </summary>
            /// <param name="runningIndex">The running index to initialize.</param>
            /// <param name="arrayPoolBuffer">This buffer memory.</param>
            public void Initialize( long runningIndex, T[] arrayPoolBuffer )
            {
                RunningIndex = runningIndex;
                _array = arrayPoolBuffer;
                _availableMemory = arrayPoolBuffer;
            }

            /// <summary>
            /// Gets whether this buffer has been freed.
            /// It may be back in the allocator's pool or lost (if the pool is full).
            /// </summary>
            public bool IsFree => _availableMemory.Length == 0;

            /// <summary>
            /// Resets the memory by freeing the buffer.
            /// Next and RunningIndex are untouched (these are under control of the allocator).
            /// </summary>
            public void Free()
            {
                IMemoryOwner<T>? memoryOwner = _memoryOwner;
                if( memoryOwner != null )
                {
                    _memoryOwner = null;
                    memoryOwner.Dispose();
                }
                else
                {
                    Debug.Assert( _array != null );
                    ArrayPool<T>.Shared.Return( _array );
                    _array = null;
                }
                Memory = default;
                _availableMemory = default;
            }

            public Memory<T> AvailableMemory => _availableMemory;

            /// <summary>
            /// Gets the number of bytes available in this segment.
            /// </summary>
            public int WritableBytes
            {
                [MethodImpl( MethodImplOptions.AggressiveInlining )]
                get => _availableMemory.Length - Memory.Length;
            }
        }
    }

}

