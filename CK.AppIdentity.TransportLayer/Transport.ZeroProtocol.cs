using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    public abstract partial class Transport
    {
        ZeroProtocol? _0Protocol;

        sealed class ZeroProtocol
        {
            readonly Transport _transport;

            public ZeroProtocol( Transport transport )
            {
                _transport = transport;
            }

            internal void Receive( TransportMessage m )
            {
                throw new NotImplementedException();
            }
        }

        ZeroProtocol EnsureZeroProtocol() => _0Protocol ??= new ZeroProtocol( this );
    }

}
