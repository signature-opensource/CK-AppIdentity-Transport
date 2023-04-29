using CK.Core;
using CK.Cris;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.Cris
{
    sealed class EventRequest<T> : Request, IEventRequest<T> where T : class, IEvent
    {
        public EventRequest( T e, ActivityMonitor.DependentToken depToken, string? authToken )
            : base( e, depToken, authToken )
        {
        }

        public T Event => Unsafe.As<T>( Payload );
    }

}
