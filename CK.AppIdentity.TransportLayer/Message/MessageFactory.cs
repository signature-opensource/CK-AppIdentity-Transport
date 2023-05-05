
#pragma warning disable CA1816 // Dispose methods should call SuppressFinalize

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Common base for message factories.
    /// </summary>
    public abstract class MessageFactory : IDisposable
    {
        MutableSequence<byte>? _oneBuffer;

        private protected MessageFactory()
        {
        }

        private protected MutableSequence<byte> GetBuffer()
        {
            return Interlocked.Exchange( ref _oneBuffer, null ) ?? new MutableSequence<byte>();
        }

        internal void Release( MutableSequence<byte> buffer )
        {
            buffer.Clear();
            Interlocked.CompareExchange( ref _oneBuffer, buffer, null );
        }

        /// <summary>
        /// Disposes any internal resource.
        /// </summary>
        public void Dispose()
        {
            Interlocked.Exchange( ref _oneBuffer, null )?.Dispose();
        }
    }

}
