using CK.Cris;

namespace CK.Testing.AppIdentity.Cris;

public interface IListenerCommand : ICommand<string>
{
    string Message { get; set; }
}
