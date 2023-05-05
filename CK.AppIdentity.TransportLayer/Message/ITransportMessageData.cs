using System.Buffers;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Read only view of a <see cref="TransportMessageImpl"/> that cannot be
    /// retained or disposed.
    /// </summary>
    public interface ITransportMessageData
    {
        /// <summary>
        /// Gets the message protocol.
        /// </summary>
        MessageProtocol Protocol { get; }

        /// <summary>
        /// Gets an optional source object associated to this <see cref="TransportMessageImpl"/>.
        /// For an outgoing message, this typically references a data object that is serialized in the message.
        /// </summary>
        object? Source { get; }

        /// <summary>
        /// Gets whether this message is valid: it is not the <see cref="TransportMessage.Invalid"/> nor the <see cref="TransportMessageImpl.Canceled"/> message
        /// and has not been disposed yet.
        /// </summary>
        bool IsValid { get; }

        /// <summary>
        /// Gets whether this message is a valid control message.
        /// </summary>
        bool IsControl { get; }

        /// <summary>
        /// Gets whether this message is a valid data message.
        /// </summary>
        bool IsData { get; }

        /// <summary>
        /// Gets the message.
        /// <see cref="IsValid"/> must be true otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        ReadOnlySequence<byte> Payload { get; }
    }
}
