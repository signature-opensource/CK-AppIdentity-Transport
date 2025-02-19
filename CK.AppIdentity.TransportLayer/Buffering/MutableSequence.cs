using System;
using System.Buffers;
using CK.Core;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Reusable and mutable <see cref="ReadOnlySequence{T}"/>.
/// <see cref="Clear"/> must be called to free its resources and use it again.
/// This is a low level implementation: it must be used with care otherwise kitten will die.
/// <para>
/// Ther is no Slice or equivalent methods and this is intended: the MutableSequence owns its linked
/// list of buffers, there cannot be multiple owners.
/// </para>
/// </summary>
/// <typeparam name="T">The type (in practice, this is a byte).</typeparam>
public sealed partial class MutableSequence<T> : IBufferWriter<T>, IDisposable where T : struct
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

    sealed class FakeArrayOwner : IMemoryOwner<T>
    {
        readonly Memory<T> _memory;

        public FakeArrayOwner( T[] memory ) => _memory = memory;

        public Memory<T> Memory => _memory;

        public void Dispose() { }
    }

    /// <summary>
    /// Adds an array of <typeparamref name="T"/>.
    /// The content of the array should not be mutated once added.
    /// Note that if this is an empty array, nothing is done.
    /// </summary>
    /// <param name="data">A non empty array.</param>
    public void AddSegment( T[] data )
    {
        Throw.CheckNotNullArgument( data );
        if( data.Length > 0 )
        {
            AddExternalMemory( new FakeArrayOwner( data ) );
        }
    }

    /// <summary>
    /// Adds a non empty data managed by another memory pool. The ownership is transfered to
    /// this sequence: the memory will be disposed by this <see cref="Clear()"/>.
    /// <para>
    /// If the <see cref="Memory{T}.Length"/> is 0 (data is empty) this throws an <see cref="ArgumentException"/>
    /// because we don't allow an empty segment and there is an ambiguity on whether Dispose() should
    /// be called or not on an empty buffer.
    /// </para>
    /// <para>
    /// The memory should not be mutated once added.
    /// </para>
    /// </summary>
    /// <param name="data">The non empty memory to add.</param>
    public void AddSegment( IMemoryOwner<T> data )
    {
        Throw.CheckNotNullArgument( data );
        Throw.CheckArgument( data.Memory.Length > 0 );
        AddExternalMemory( data );
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
    /// <returns>This sequence content.</returns>
    public ReadOnlySequence<T> GetReadOnlySequence() => _head == null
                                                            ? ReadOnlySequence<T>.Empty
                                                            : new ReadOnlySequence<T>( _head, 0, _tail!, _tail!.Length );

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
            Throw.DebugAssert( segment.Next != null || _tail == segment );
            segment = segment.Next;
        }
        if( count > 0 )
        {
            Throw.DebugAssert( _head != null && _tail != null );
            if( count == 1 ) ReleaseSegment( _head );
            else ReleaseSegments( _head, _tail, count );
            _head = null;
            _tail = null;
            _tailMemory = default;
            _bytesBuffered = 0;
        }
    }

    void AddExternalMemory( IMemoryOwner<T> external )
    {
        Throw.DebugAssert( external.Memory.Length > 0 );
        // Obtains a segment dedicated to the external memory.
        var newSegment = GetCachedSegmentOrCreateOne();
        // Enlists this new segment in the current sequence and computes
        // its RunningIndex.
        // If this is the very first segment, we have no _head nor _tail.
        long runningIndex;
        if( _head == null )
        {
            Throw.DebugAssert( _tail == null && _bytesBuffered == 0 );
            _head = _tail = newSegment;
            runningIndex = 0;
        }
        else
        {
            Throw.DebugAssert( _tail != null );
            runningIndex = _tail.RunningIndex + _tail.Length;
            _tail.Next = newSegment;
            _tail = newSegment;
        }
        // The running index is known: initialize the segment on the external memory.
        newSegment.InitializeExternal( runningIndex, external );
        // This leaves this sequence in "full" state (a new segment will be required).
        _tailMemory = Memory<T>.Empty;
        _bytesBuffered += external.Memory.Length;
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
            Throw.DebugAssert( _tail != null );
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

    /// <summary>
    /// Only called by <see cref="AllocateMemory(int)"/>
    /// </summary>
    Segment AllocateSegment( long runningIndex, int sizeHint )
    {
        Throw.DebugAssert( sizeHint >= 0 );
        var newSegment = GetCachedSegmentOrCreateOne();
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

    MutableSequence<T>.Segment GetCachedSegmentOrCreateOne()
    {
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
        Throw.DebugAssert( segment.IsFree );
        if( _freeSegmentSize < _freeSegmentMaxSize )
        {
            segment.Next = _freeSegmentHead;
            _freeSegmentHead = segment;
            ++_freeSegmentSize;
        }
    }

    void ReleaseSegments( Segment head, Segment tail, int count )
    {
        Throw.DebugAssert( head.IsFree && tail.IsFree );
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
            Throw.DebugAssert( n != null && n.IsFree );
            head.Next = _freeSegmentHead;
            _freeSegmentHead = head;
            head = n;
        }
        _freeSegmentSize = _freeSegmentMaxSize;
    }
}

