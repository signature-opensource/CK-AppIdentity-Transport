using CK.Cris;

namespace CK.Testing.AppIdentity.Cris;

public interface ISenderCommand : ICommand<string>
{
    string Message { get; set; }
}
