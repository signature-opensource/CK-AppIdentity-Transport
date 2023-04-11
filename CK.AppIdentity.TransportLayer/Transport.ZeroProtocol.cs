using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    public abstract partial class Transport
    {
        ZeroProtocol? _0Protocol;

        ZeroProtocol EnsureZeroProtocol() => _0Protocol ??= new ZeroProtocol( this );

        sealed class ZeroProtocol
        {
            readonly Transport _transport;

            public ZeroProtocol( Transport transport )
            {
                _transport = transport;
            }

            internal void Receive( TransportManager transportManager, TransportMessage m )
            {
                Debug.Assert( m.Protocol == MessageProtocol.ZeroProtocol );
                if( m == TransportMessage.Empty )
                {
                    transportManager.TransportKeepAliveReceived( _transport );
                }
                else
                {
                    transportManager.Logger.Warn( $"Received unknown '0 Protocol' message. Ignoring it." );
                }
            }
        }
    }

}
