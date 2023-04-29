using CK.Core;
using CK.Cris;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.Cris
{
    sealed class EventRequest<T> : RequestBase, IEventRequest<T> where T : class, IEvent
    {
        public EventRequest( T e, ActivityMonitor.DependentToken depToken )
            : base( e, depToken )
        {
        }

        public T Event => Unsafe.As<T>( Payload );
    }

}
