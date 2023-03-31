using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Internal interface that generalizes <see cref="ServerMessageHandler"/> and <see cref="ClientMessageHandler"/>.
    /// </summary>
    interface IMessageHandler
    {
        ValueTask ReceiveAsync( MessageEndPoint endPoint, TransportMessage message );

        /// <summary>
        /// Called when a <see cref="MessageEndPoint"/> is dead.
        /// </summary>
        /// <param name="endPoint">The dead end point.</param>
        /// <param name="potentialRecycling">
        /// Can be non null only when listening (server mode) in <see cref="ListeningMode.Default"/> and when
        /// this new Transport is replacing the available one: the new one is killing the current one.
        /// </param>
        /// <returns>The awaitable.</returns>
        ValueTask OnDisconnectedAsync( IActivityMonitor monitor, MessageEndPoint endPoint, Transport? potentialRecycling );

        /// <summary>
        /// Tries to save the messages from a dead endpoint by injecting them into
        /// an alive one (<see cref="ListeningMode.RoundRobin"/>) or all the alive ones (<see cref="ListeningMode.Parallel"/>).
        /// </summary>
        /// <param name="m">The message to save.</param>
        /// <returns>True if the message has successfully been transfered.</returns>
        bool TryEnqueueUnsentMessages( TransportMessage m );
    }
}
