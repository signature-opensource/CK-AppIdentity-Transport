using CK.Core;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.TransportLayer
{
    public sealed partial class MutableSequence<T> where T : struct
    {
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
                    Throw.DebugAssert( value <= AvailableMemory.Length );
                    Memory = AvailableMemory.Slice( 0, value );
                }
            }

            /// <summary>
            /// Masked to be a Segment rather than ReadOnlySequenceSegment of bytes.
            /// </summary>
            internal new Segment? Next
            {
                get => Unsafe.As<Segment?>( base.Next );
                set => base.Next = value;
            }

            /// <summary>
            /// Initializes this buffer with a memory from a pool.
            /// </summary>
            /// <param name="runningIndex">The running index to initialize.</param>
            /// <param name="memoryOwner">This buffer memory's owner.</param>
            internal void Initialize( long runningIndex, IMemoryOwner<T> memoryOwner )
            {
                RunningIndex = runningIndex;
                _memoryOwner = memoryOwner;
                _availableMemory = memoryOwner.Memory;
            }

            /// <summary>
            /// Initializes this buffer with a memory from an external pool: the memory is filled.
            /// </summary>
            /// <param name="runningIndex">The running index to initialize.</param>
            /// <param name="memoryOwner">This buffer memory's owner.</param>
            internal void InitializeExternal( long runningIndex, IMemoryOwner<T> memoryOwner )
            {
                RunningIndex = runningIndex;
                _memoryOwner = memoryOwner;
                Memory = memoryOwner.Memory;
                _availableMemory = default;
            }

            /// <summary>
            /// Initializes this buffer with an array from the shared pool.
            /// </summary>
            /// <param name="runningIndex">The running index to initialize.</param>
            /// <param name="arrayPoolBuffer">This buffer memory.</param>
            internal void Initialize( long runningIndex, T[] arrayPoolBuffer )
            {
                RunningIndex = runningIndex;
                _array = arrayPoolBuffer;
                _availableMemory = arrayPoolBuffer;
            }

            /// <summary>
            /// Gets whether this buffer has been freed.
            /// It may be back in the allocator's pool or lost (if the pool is full).
            /// </summary>
            internal bool IsFree => _availableMemory.Length == 0;

            /// <summary>
            /// Resets the memory by freeing the buffer.
            /// Next and RunningIndex are untouched (these are under control of the allocator).
            /// </summary>
            internal void Free()
            {
                IMemoryOwner<T>? memoryOwner = _memoryOwner;
                if( memoryOwner != null )
                {
                    _memoryOwner = null;
                    memoryOwner.Dispose();
                }
                else
                {
                    Throw.DebugAssert( _array != null );
                    ArrayPool<T>.Shared.Return( _array );
                    _array = null;
                }
                Memory = default;
                _availableMemory = default;
            }

            internal Memory<T> AvailableMemory => _availableMemory;

            /// <summary>
            /// Gets the number of bytes available in this segment.
            /// </summary>
            internal int WritableBytes
            {
                [MethodImpl( MethodImplOptions.AggressiveInlining )]
                get => _availableMemory.Length - Memory.Length;
            }
        }
    }

}

