using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.PocoChannel
{
    /// <summary>
    /// Extends <see cref="IBufferWriter{T}"/> to gives access to its written content.
    /// It is possible to modify the content after it has been written (typically to update
    /// a packet's length that has been reserved at the beginning of the buffer), before sending
    /// and clearing the buffer.
    /// <para>
    /// This may be extended in the future to support deletions and insertions (but this would need
    /// to encapsulate almost all the aspects of the memory management to stay on the safe side).
    /// May be some "MemoryWindow" that once obtained will be tracked and updated.
    /// As long as fixed size parts (i.e. non variable field size) are used, this is not required.
    /// </para>
    /// </summary>
    /// <typeparam name="T">The type of the items.</typeparam>
    public interface IBufferEditor<T> : IBufferWriter<T>
    {
        /// <summary>
        /// Clears this editor.
        /// </summary>
        void Clear();

        /// <summary>
        /// Gets the count of bytes in this editor.
        /// </summary>
        long Length { get; }

        /// <summary>
        /// Gets a <see cref="ReadOnlySequence{T}"/> of this buffer content.
        /// By using <see cref="MemoryMarshal.AsMemory{T}(ReadOnlyMemory{T})"/>, each segment
        /// can be modified.
        /// </summary>
        /// <returns>This editor's content.</returns>
        ReadOnlySequence<T> GetReadOnlySequence();
    }
}

