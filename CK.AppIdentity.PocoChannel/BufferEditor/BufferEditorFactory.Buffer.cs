using System.Buffers;
using System.Diagnostics;
using CK.Core;

namespace CK.AppIdentity.PocoChannel
{
    public sealed partial class BufferEditorFactory
    {
        /// <summary>
        /// Reusable buffer (<see cref="Clear"/> must be called to free its resources and use it again).
        /// </summary>
        public sealed class Buffer : IBufferEditor<byte>, IDisposable
        {
            readonly BufferEditorFactory _allocator;
            BufferSegment? _head;
            BufferSegment? _tail;
            Memory<byte> _tailMemory;
            int _bytesBuffered;

            internal Buffer( BufferEditorFactory allocator )
            {
                _allocator = allocator;
            }

            /// <summary>
            /// Dispose this buffer.
            /// This simply call <see cref="Clear"/>: a disposed buffer can actually be reused.
            /// </summary>
            public void Dispose()
            {
                Clear();
            }

            /// <inheritdoc />
            public void Advance( int bytes )
            {
                Throw.CheckArgument( (uint)bytes <= (uint)_tailMemory.Length );
                _bytesBuffered += bytes;
                _tail!.Length += bytes;
                _tailMemory = _tailMemory.Slice( bytes );
            }

            /// <inheritdoc />
            public Memory<byte> GetMemory( int sizeHint = 0 )
            {
                Throw.CheckOutOfRangeArgument( sizeHint >= 0 );
                AllocateMemory( sizeHint );
                return _tailMemory;
            }

            /// <inheritdoc />
            public Span<byte> GetSpan( int sizeHint = 0 )
            {
                Throw.CheckOutOfRangeArgument( sizeHint >= 0 );
                AllocateMemory( sizeHint );
                return _tailMemory.Span;
            }

            /// <summary>
            /// Gets the count of bytes in this buffer.
            /// </summary>
            public long Length => _bytesBuffered;

            /// <summary>
            /// Gets the bytes of this buffer.
            /// </summary>
            /// <returns>A read only sequence of bytes.</returns>
            public ReadOnlySequence<byte> GetReadOnlySequence() => _head == null
                                                                    ? ReadOnlySequence<byte>.Empty
                                                                    : new ReadOnlySequence<byte>( _head, 0, _tail!, _tail!.Length );
            /// <summary>
            /// Clears this buffer. It can be reused.
            /// </summary>
            public void Clear()
            {
                int count = 0;
                BufferSegment? segment = _head;
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
                    if( count == 1 ) _allocator.ReleaseSegment( _head );
                    else _allocator.ReleaseSegments( _head, _tail, count );
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
                    // We need to allocate memory to write since nobody has written before
                    BufferSegment newSegment = _allocator.AllocateSegment( 0, sizeHint );
                    _tailMemory = newSegment.AvailableMemory;
                    _head = _tail = newSegment;
                }
                else
                {
                    Debug.Assert( _tail != null );
                    int bytesLeftInBuffer = _tailMemory.Length;

                    // sizeHint is 0 by default ("Give me whatever you have").
                    // In such case if there is no more room at all we must allocate.
                    if( bytesLeftInBuffer == 0 || bytesLeftInBuffer < sizeHint )
                    {
                        BufferSegment newSegment = _allocator.AllocateSegment( _tail.RunningIndex + _tail.Length, sizeHint );
                        _tailMemory = newSegment.AvailableMemory;
                        _tail.Next = newSegment;
                        _tail = newSegment;
                    }
                }
            }

        }
    }
}

