using System;
using System.Buffers;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.PocoChannel
{
    public sealed partial class BufferEditorFactory
    {
        sealed class BufferSegment : ReadOnlySequenceSegment<byte>
        {
            IMemoryOwner<byte>? _memoryOwner;
            byte[]? _array;
            Memory<byte> _availableMemory;

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
            /// Masked to be a BufferSegment rather than ReadOnlySequenceSegment of bytes.
            /// This is under control of the allocator.
            /// </summary>
            public new BufferSegment? Next
            {
                get => Unsafe.As<BufferSegment?>( base.Next );
                set => base.Next = value;
            }

            /// <summary>
            /// Initializes this buffer with a memory from a pool.
            /// </summary>
            /// <param name="runningIndex">The running index to initialize.</param>
            /// <param name="memoryOwner">This buffer memory's owner.</param>
            public void Initialize( long runningIndex, IMemoryOwner<byte> memoryOwner )
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
            public void Initialize( long runningIndex, byte[] arrayPoolBuffer )
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
                IMemoryOwner<byte>? memoryOwner = _memoryOwner;
                if( memoryOwner != null )
                {
                    _memoryOwner = null;
                    memoryOwner.Dispose();
                }
                else
                {
                    Debug.Assert( _array != null );
                    ArrayPool<byte>.Shared.Return( _array );
                    _array = null;
                }
                Memory = default;
                _availableMemory = default;
            }

            public Memory<byte> AvailableMemory => _availableMemory;

            /// <summary>
            /// Gets the number of bytes available in this segment.
            /// </summary>
            public int WritableBytes
            {
                [MethodImpl( MethodImplOptions.AggressiveInlining )]
                get => _availableMemory.Length - Memory.Length;
            }

            /// <summary>
            /// Updates this <see cref="ReadOnlySequenceSegment{T}.RunningIndex"/>
            /// and the ones of the <see cref="Next"/> segments.
            /// </summary>
            /// <param name="i">The new running index.</param>
            public void SetRunningIndex( long i )
            {
                Debug.Assert( i >= 0 );
                RunningIndex = i;

                var segment = this;
                while( segment.Next != null )
                {
                    i += segment.Length;
                    segment = segment.Next;
                    segment.RunningIndex = i;
                }
            }

            [MethodImpl( MethodImplOptions.AggressiveInlining )]
            internal static long GetLength( BufferSegment startSegment, int startIndex, BufferSegment endSegment, int endIndex )
            {
                return (endSegment.RunningIndex + (uint)endIndex) - (startSegment.RunningIndex + (uint)startIndex);
            }

            [MethodImpl( MethodImplOptions.AggressiveInlining )]
            internal static long GetLength( long startPosition, BufferSegment endSegment, int endIndex )
            {
                return (endSegment.RunningIndex + (uint)endIndex) - startPosition;
            }
        }
    }
}

