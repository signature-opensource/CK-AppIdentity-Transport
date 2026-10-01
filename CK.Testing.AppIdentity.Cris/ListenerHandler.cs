using CK.Core;
using CK.Cris;

namespace CK.Testing.AppIdentity.Cris;

public class ListenerHandler : IAutoService
{
    [CommandHandler]
    public string Handle( ISenderCommand c )
    {
        return $"Listener received '{c.Message}'.";
    }
}
