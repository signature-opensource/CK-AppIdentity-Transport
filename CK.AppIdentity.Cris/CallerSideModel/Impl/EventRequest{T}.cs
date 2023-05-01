using CK.Core;
using CK.Cris;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.Cris
{
    sealed class EventRequest<T> : OutgoingRequest, IEventRequest<T> where T : class, IEvent
    {
        public EventRequest( OutgoingRequestCache cache, T e, ActivityMonitor.Token issuerToken, object? extraData )
            : base( cache, e, issuerToken, extraData )
        {
        }

        public T Event => Unsafe.As<T>( Payload );
    }

}
