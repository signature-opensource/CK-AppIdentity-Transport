using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    public abstract class PeerProtocolHandler
    {
        /// <summary>
        /// Called for each message received (same protocol version).
        /// </summary>
        /// <param name="endPoint">The receiving end point.</param>
        /// <param name="message">The message that must be disposed once done with it.</param>
        /// <returns>The awaitable.</returns>
        internal protected abstract ValueTask ReceiveAsync( MessageEndPoint endPoint, TransportMessage message );

    }
}
