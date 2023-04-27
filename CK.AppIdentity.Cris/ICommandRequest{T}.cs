using CK.Cris;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Strongly typed request of <typeparamref name="T"/> command.
    /// </summary>
    /// <typeparam name="T">Type of the command.</typeparam>
    public interface ICommandRequest<T> : ICommandRequest where T : class, ICommand
    {
        /// <inheritdoc cref="ICommandRequest.Command"/>
        new T Command { get; }
    }
}
