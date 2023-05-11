using System.Buffers;

namespace CK.AppIdentity.TransportLayer
{
    public interface IMessage : IDisposable
    {
        bool IsControl { get; }
        bool IsData { get; }
        ReadOnlySequence<byte> Payload { get; }
        MessageProtocol Protocol { get; }
        object? Source { get; set; }
    }
}
