using CK.Core;
using CK.Cris;

namespace CK.Testing.AppIdentity.Cris;

public class SenderHandler : IAutoService
{
    [CommandHandler]
    public string Handle( IListenerCommand c )
    {
        return $"Sender received '{c.Message}'.";
    }
}
