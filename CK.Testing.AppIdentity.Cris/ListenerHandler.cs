using CK.AppIdentity;
using CK.Auth;
using CK.Core;
using CK.Cris;
using System.Threading.Tasks;

namespace CK.Testing.AppIdentity.Cris;

public class ListenerHandler : IAutoService
{
    [CommandHandler]
    public async Task<string> HandleAsync( ISenderCommand c, ICrisCommandContext context )
    {
        await context.EmitEventAsync<IListenerImmediateEvent>( e => e.Message = $"Handling '{c.Message}'." );
        return $"Listener received '{c.Message}'.";
    }

    [CommandHandler]
    public string Handle( IWhoAmICommand c, IRemoteParty caller, IAuthenticationInfo authInfo )
    {
        return $"{caller.FullName}/{authInfo.User.UserName}";
    }
}
