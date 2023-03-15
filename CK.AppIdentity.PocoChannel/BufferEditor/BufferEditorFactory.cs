using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;

namespace CK.AppIdentity.PocoChannel
{
    /// <summary>
    /// Factory of <see cref="Buffer"/> that are disposable <see cref="IBufferEditor{T}"/>.
    /// This factory caches internal buffer segments that are <see cref="ReadOnlySequenceSegment{T}"/> and can be reused
    /// across buffers if needed: this factory only caches and reuses up to 256 segments (above, they are GC'ed) and segments
    /// are very small objects (it is the Buffer that holds the segments memory and are released when calling <see cref="Buffer.Clear()"/>).
    /// <para>
    /// More than one Buffer can exist at the same time BUT NOT concurrently: all of this is NOT thread safe.
    /// When sending, this may be convenient to write a "multi-part" message where each part can have its own buffer or when a "high-level message"
    /// must produce more than one serialized form. When receiving it may be used to open sub sections (with their own, independent, ReadOnlySequence).
    /// </para>
    /// </summary>
    public sealed partial class BufferEditorFactory
    {
        // This is holds 1MB since buffers are 4K.
        // When more than this is required, buffers are no more
        // reused.
        const int MaxSegmentPoolSize = 256; // 1MB

        readonly int _minimumBufferSize;
        readonly int _maxPooledBufferSize;
        readonly MemoryPool<byte>? _pool;
        BufferSegment? _poolHead;
        int _poolSize;

        /// <summary>
        /// Initializes a new allocator with <see cref="BufferEditorFactoryOptions.Default"/>.
        /// </summary>
        public BufferEditorFactory()
            : this( BufferEditorFactoryOptions.Default )
        {
        }

        /// <summary>
        /// Initializes a new allocator with specific options.
        /// </summary>
        public BufferEditorFactory( BufferEditorFactoryOptions options )
        {
            _minimumBufferSize = options.MinimumBufferSize;
            _pool = options.Pool == MemoryPool<byte>.Shared ? null : options.Pool;
            _maxPooledBufferSize = _pool?.MaxBufferSize ?? -1;
            _poolHead = null;
        }

        /// <summary>
        /// Creates a new <see cref="Buffer"/>.
        /// It must be disposed once done with it. A buffer is not thread safe and alive buffers obtained from the same
        /// factory are not thread safe either. 
        /// </summary>
        /// <returns>A buffer of segments.</returns>
        public Buffer CreateBuffer() => new Buffer( this );

        BufferSegment AllocateSegment( long runningIndex, int sizeHint )
        {
            Debug.Assert( sizeHint >= 0 );
            BufferSegment? newSegment = _poolHead;
            if( newSegment != null )
            {
                _poolHead = newSegment.Next;
                newSegment.Next = null;
                --_poolSize;
            }
            else
            {
                newSegment = new BufferSegment();
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
                newSegment.Initialize( runningIndex, ArrayPool<byte>.Shared.Rent( sizeToRequest ) );
            }
            return newSegment;
        }

        int GetSegmentSize( int sizeHint, int maxBufferSize = int.MaxValue )
        {
            // First we need to handle case where hint is smaller than minimum segment size
            sizeHint = Math.Max( _minimumBufferSize, sizeHint );
            // After that adjust it to fit into pools max buffer size
            var adjustedToMaximumSize = Math.Min( maxBufferSize, sizeHint );
            return adjustedToMaximumSize;
        }

        void ReleaseSegment( BufferSegment segment )
        {
            if( _poolSize < MaxSegmentPoolSize )
            {
                segment.Next = _poolHead;
                _poolHead = segment;
                ++_poolSize;
            }
        }

        void ReleaseSegments( BufferSegment head, BufferSegment tail, int count )
        {
            int newPoolSize = _poolSize + count;
            if( newPoolSize <= MaxSegmentPoolSize )
            {
                tail.Next = _poolHead;
                _poolHead = head;
                _poolSize = newPoolSize;
            }
            else
            {
                ReleaseSegmentsSlow( head );
            }
        }

        void ReleaseSegmentsSlow( BufferSegment head )
        {
            var keep = MaxSegmentPoolSize - _poolSize;
            for( int i = 0; i < keep; ++i )
            {
                var n = head.Next;
                Debug.Assert( n != null );
                head.Next = _poolHead;
                _poolHead = head;
                head = n;
            }
            _poolSize = MaxSegmentPoolSize;
        }
    }
}

