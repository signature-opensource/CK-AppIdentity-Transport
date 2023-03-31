using CK.Core;
using System.Diagnostics;
using System.Text;

namespace CK.AppIdentity.TransportLayer
{
    partial class ZeroProtocol
    {
        readonly TransportManager _transportManager;
        readonly Transport _transport;

        public ZeroProtocol( TransportManager transportManager, Transport transport )
        {
            _transportManager = transportManager;
            _transport = transport;
        }


    }
}
