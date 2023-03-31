namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Common base for message factories.
    /// </summary>
    public abstract class MessageFactory : IDisposable
    {
        internal const int _maxPrefixLength = 5;

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
