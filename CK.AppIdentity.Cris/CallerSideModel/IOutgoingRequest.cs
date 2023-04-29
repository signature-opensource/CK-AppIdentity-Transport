using CK.Core;
using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// A command request carries the <see cref="Payload"/> and the eventual <see cref="RequestCompletion"/>.
    /// of a <see cref="IEvent"/>, <see cref="ICommand"/> or <see cref="ICommand{TResult}"/>.
    /// <para>
    /// This non generic interface generalizes <see cref="IEventRequest{T}"/> and <see cref="ICommandRequest{T}"/>.
    /// </para>
    /// </summary>
    public interface IOutgoingRequest
    {
        /// <summary>
        /// Gets the <see cref="ICrisEvent"/>, <see cref="ICommand"/> or <see cref="ICommand{TResult}"/>.
        /// </summary>
        ICrisPoco Payload { get; }

        /// <summary>
        /// Gets a token that identifies the initialization of this request.
        /// </summary>
        ActivityMonitor.DependentToken IssuerToken { get; }

        /// <summary>
        /// Gets the UTC date and time creation of this request.
        /// </summary>
        DateTime CreationDate { get; }

        /// <summary>
        /// Gets a task that is completed when this request has been sent.
        /// </summary>
        Task<DateTime> SentDate { get; }

        /// <summary>
        /// Gets a task that is completed when the request is terminated.
        /// The task's value can be:
        /// <list type="bullet">
        ///  <item>A <see cref="ICrisResultError"/> on validation or execution error by the callee.</item>
        ///  <item>A successful null result on success when <see cref="Payload"/> is a <see cref="ICrisEvent"/> or a <see cref="ICommand"/>.</item>
        ///  <item>A successful result object if Payload is a <see cref="ICommand{TResult}"/>.</item>
        /// </list>
        /// </summary>
        Task<object?> RequestCompletion { get; }
    }
}
