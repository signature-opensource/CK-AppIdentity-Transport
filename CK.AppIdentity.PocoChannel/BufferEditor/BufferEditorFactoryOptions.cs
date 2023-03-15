using System.Buffers;
using CK.Core;

namespace CK.AppIdentity.PocoChannel
{
    /// <summary>
    /// Options for <see cref="BufferEditorFactory"/>.
    /// </summary>
    public sealed class BufferEditorFactoryOptions
    {
        /// <summary>
        /// Default minimum buffer size is 4096 bytes.
        /// </summary>
        public const int DefaultMinimumBufferSize = 4096;

        /// <summary>
        /// Default maximum buffer size is 2 GiB.
        /// </summary>
        public const int DefaultMaximumBufferSize = int.MaxValue;

        /// <summary>
        /// Default options. Pool is <c>MemoryPool&lt;byte&gt;.Shared</c> and minimum buffer size is 4096 bytes.
        /// </summary>
        public static readonly BufferEditorFactoryOptions Default = new BufferEditorFactoryOptions();

        /// <summary>
        /// Initializes a <see cref="BufferEditorFactoryOptions" /> instance, optionally specifying a memory pool and a minimum buffer size.</summary>
        /// <param name="pool">The memory pool to use when allocating memory. Defaults to <c>MemoryPool&lt;byte&gt;.Shared</c>.</param>
        /// <param name="minimumBufferSize">The minimum buffer size to use when renting memory from the <paramref name="pool" />. Must be at least 16. The default value is 4096.</param>
        /// <param name="maximumBufferSize">The maximum buffer size to use when renting memory from the <paramref name="pool" />. The default value is <see cref="int.MaxValue"/>.</param>
        public BufferEditorFactoryOptions( MemoryPool<byte>? pool = null, int minimumBufferSize = -1, int maximumBufferSize = -1 )
        {
            Pool = pool ?? MemoryPool<byte>.Shared;

            MinimumBufferSize =
                minimumBufferSize == -1 ? DefaultMinimumBufferSize :
                minimumBufferSize < 16 ? Throw.ArgumentOutOfRangeException<int>( nameof( minimumBufferSize ), "Cannot be smaller than 16." ) :
                minimumBufferSize;
            Throw.CheckArgument( maximumBufferSize >= MinimumBufferSize );
            MaximumBufferSize = maximumBufferSize;
        }

        /// <summary>
        /// Gets the minimum buffer size to use when renting memory from the <see cref="Pool"/>.
        /// It cannot be less than 16 bytes.
        /// </summary>
        public int MinimumBufferSize { get; }

        /// <summary>
        /// Gets the maximum buffer size to use when renting memory from the <see cref="Pool"/>.
        /// </summary>
        public int MaximumBufferSize { get; }

        /// <summary>
        /// Gets the <see cref="MemoryPool{T}" /> to use when allocating memory.
        /// Defaults to <c>MemoryPool&lt;byte&gt;.Shared</c>.
        /// </summary>
        public MemoryPool<byte> Pool { get; }
    }
}

