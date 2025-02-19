using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Strongly typed outgoing <typeparamref name="T"/> command.
/// </summary>
/// <typeparam name="T">Type of the command.</typeparam>
public interface IOutgoingCommand<T> : IOutgoingCommand where T : class, IAbstractCommand
{
    /// <summary>
    /// Offers strongly types for the both the command and its result.
    /// This must be called only for <see cref="ICommand{TResult}"/> otherwise
    /// an <see cref="ArgumentException"/> is thrown.
    /// </summary>
    /// <typeparam name="TResult">The expected result type.</typeparam>
    public interface WithResult<TResult> : IOutgoingCommand<T>
    {
        /// <summary>
        /// Gets a task that is completed with a successful result or with an exception
        /// if <see cref="IOutgoingCommand.RequestCompletion"/> is a <see cref="ICrisResultError"/>.
        /// </summary>
        Task<TResult> Result { get; }
    }

    /// <summary>
    /// Gets the command.
    /// </summary>
    T Command { get; }

}
