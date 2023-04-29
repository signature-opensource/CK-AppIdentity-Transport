using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Factory for outgoing <see cref="IEventRequest{T}"/> and <see cref="ICommandRequest{T}"/> requests.
    /// <para>
    /// This must be used by endpoint implementations.
    /// </para>
    /// </summary>
    static class OutgoingRequest
    {
        /// <summary>
        /// Creates a new event request.
        /// </summary>
        /// <typeparam name="T">The type of the event.</typeparam>
        /// <param name="monitor">The <see cref="IActivityMonitor"/> or <see cref="IParallelLogger"/> to use to generate the <see cref="IOutgoingRequest.IssuerToken"/>.</param>
        /// <param name="e">The event payload.</param>
        /// <returns>A new event request.</returns>
        public static IEventRequest<T> CreateEvent<T>( IActivityDependentTokenFactory monitor, T e ) where T : class, IEvent
        {
            var token = monitor.CreateDependentToken( null, $"Handling '{e.CrisPocoModel.PocoName}' event." );
            return new EventRequest<T>( e, token );
        }

        /// <summary>
        /// Creates a new event request.
        /// </summary>
        /// <typeparam name="T">The type of the event.</typeparam>
        /// <param name="e">The event payload.</param>
        /// <param name="token">The <see cref="IOutgoingRequest.IssuerToken"/>.</param>
        /// <returns>A new event request.</returns>
        public static IEventRequest<T> CreateEvent<T>( T e, ActivityMonitor.DependentToken token ) where T : class, IEvent
        {
            return new EventRequest<T>( e, token );
        }

        /// <summary>
        /// Creates a new command request.
        /// </summary>
        /// <typeparam name="T">The type of the command.</typeparam>
        /// <param name="monitor">The <see cref="IActivityMonitor"/> or <see cref="IParallelLogger"/> to use to generate the <see cref="IOutgoingRequest.IssuerToken"/>.</param>
        /// <param name="c">The command payload.</param>
        /// <returns>A new command request.</returns>
        public static ICommandRequest<T> CreateCommand<T>( IActivityDependentTokenFactory monitor, T c ) where T : class, IAbstractCommand
        {
            var token = monitor.CreateDependentToken( null, $"Handling '{c.CrisPocoModel.PocoName}' command." );
            return new CommandRequest<T>( c, token );
        }

        /// <summary>
        /// Creates a new command request.
        /// </summary>
        /// <typeparam name="T">The type of the command.</typeparam>
        /// <param name="e">The event payload.</param>
        /// <param name="token">The <see cref="IOutgoingRequest.IssuerToken"/>.</param>
        /// <returns>A new command request.</returns>
        public static ICommandRequest<T> CreateCommand<T>( T c, ActivityMonitor.DependentToken token ) where T : class, IAbstractCommand
        {
            return new CommandRequest<T>( c, token );
        }
    }
}
