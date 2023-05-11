using System.Buffers;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    internal sealed class StaticTransportMessageImpl : ITransportMessage, IMessage
    {
        internal StaticTransportMessageImpl( MessageProtocol protocol, ReadOnlySequence<byte> message, bool isControl )
        {
            Debug.Assert( message.IsSingleSegment );
            Protocol = protocol;
            Payload = message;
            IsControl = isControl;
        }

        public MessageProtocol Protocol { get; }

        public object? Source
        {
            get => null;
            set => throw new NotSupportedException();
        }

        public bool IsValid => true;

        public bool IsControl { get; }

        public bool IsData => !IsControl;

        public ReadOnlySequence<byte> Payload { get; }

        public void Dispose() { }

        public void Retain() { }
    }
}
