using CK.Cris;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// <summary>
    /// Strongly typed request of a <see cref="ICommand{TResult}"/>.
    /// </summary>
    /// <typeparam name="T">Type of the command.</typeparam>
    /// <typeparam name="TResult">Type of the result.</typeparam>
    public interface ICommandRequest<T, TResult> : ICommandRequest<T> where T : class, ICommand<TResult>
    {
        /// <summary>
        /// Gets a task that is completed with a successful result or with an exception
        /// if <see cref="ICommandRequest.Completion"/> has an error.
        /// </summary>
        Task<TResult> Result { get; }
    }

}
