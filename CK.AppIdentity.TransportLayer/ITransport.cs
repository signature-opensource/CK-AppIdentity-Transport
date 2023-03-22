using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Transport abstraction: a transport can send and receive <see cref="TransportMessage"/>.
    /// </summary>
    public interface ITransport
    {
        /// <summary>
        /// Reads the next incoming <see cref="TransportMessage"/>. Once done with it, <see cref="TransportMessage.Dispose()"/>
        /// must be called.
        /// <para>
        /// This must obviously be called sequentially otherwise kittens will die.
        /// </para>
        /// <para>
        /// This raises any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/> if
        /// <paramref name="cancellation"/> token has been signaled, in such case <see cref="TransportMessage.Canceled"/> is returned.
        /// When <see cref="TransportMessage.Invalid"/> is returned it means that an invalid length prefix has been read or it exceeds
        /// the <paramref name="maxMessageLength"/> parameter: in an case, an invalid message condemns this transport (just like an exception). 
        /// </para>
        /// </summary>
        /// <param name="maxMessageLength">Optional maximal message length. Defaults to <see cref="int.MaxValue"/> (2 GiB).</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>
        /// A message that may be one of the <see cref="TransportMessage.Invalid"/>, <see cref="TransportMessage.Canceled"/> or <see cref="TransportMessage.Empty"/>
        /// special messages.
        /// </returns>
        Task<TransportMessage> ReadNextAsync( int maxMessageLength = -1, CancellationToken cancellation = default );

        /// <summary>
        /// Sends a <see cref="TransportMessage"/> that must be <see cref="TransportMessage.IsValid"/> otherwise
        /// an <see cref="ArgumentException"/> is thrown.
        /// <para>
        /// This can be called concurrently, either an <see cref="AsyncLock"/> is used to serialize the calls OR the underlying protocol
        /// supports "parallel communication streams": the caller never need to deal with this.
        /// </para>
        /// <para>
        /// This throws any error thrown by the underlying transport.
        /// This always returns true except if the operation was canceled and the <paramref name="cancellation"/> token has been signaled.
        /// </para>
        /// </summary>
        /// <param name="message">The valid message to send.</param>
        /// <param name="cancellation">Optional cancellation token.</param>
        /// <returns>True if the message has been sent, false it <paramref name="cancellation"/> has been signaled.</returns>
        ValueTask<bool> SendAsync( TransportMessage message, CancellationToken cancellation = default );
    }

}
