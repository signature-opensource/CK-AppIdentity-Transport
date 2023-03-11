using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{

    public interface ICrisEndPointCommands
    {
        Task<ICrisResult> SendCommandAndWaitResultAsync( IActivityMonitor monitor, ICommand command );
    }
}
