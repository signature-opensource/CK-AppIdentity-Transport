using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{

    public sealed partial class TransportManager
    {
        async ValueTask DisposeListenersAsync( IActivityMonitor monitor )
        {
            // No concurrency issues: see below.
            monitor.Trace( $"Disposing listeners: '{_listeners.Select( l => l.ToString()).Concatenate()}" );
            foreach( var exists in _listeners )
            {
                try
                {
                    await exists.DisposeAsync( monitor );
                }
                catch( Exception ex )
                {
                    monitor.Error( $"While disposing {exists}.", ex );
                }
            }
        }

        /// <summary>
        /// Ensures that a listener is setup on the <paramref name="endPoint"/>.
        /// The listener should be as ready as possible to handle incoming connections.
        /// <para>
        /// We want this to be called before starting anything as a configuration validation
        /// (this is called by TransportFeatureDriver.SetupAsync and SetupDynamicRemoteAsync).
        /// Since there should not be a lot of endpoint and even if it's the case, not a lot of
        /// calls on this (only called while creating remotes). There is NO concurrent calls to
        /// TryEnsureListener.
        /// The only concurrent access is between TryEnsureListener and DisposeListeners and these 2 are
        /// non concurrent by design:
        /// - TryEnsureListener is called in the ApplicationIdentity loop (SetupAsync and SetupDynamicRemoteAsync).
        /// - DisposeListeners is called in the TransportManager loop (by the Stop()) but it is itself called
        /// by the ApplicationIdentity loop -> TransportFeatureDriver.TeardownAsync that awaits the _transportManager.RunningTask.
        /// </para>
        /// </summary>
        /// <param name="monitor">The monitor to signal errors.</param>
        /// <param name="endPoint">The listening address.</param>
        /// <returns>The listener on success, null otherwise.</returns>
        internal TransportListener? TryEnsureListener( IActivityMonitor monitor, TransportTypeAddress endPoint )
        {
            Debug.Assert( IsInApplicationIdentityLoop( monitor ) );

            foreach( var exists in _listeners )
            {
                if( exists.IsListeningAddress( endPoint.TypedAddress ) )
                {
                    return exists;
                }
            }
            var l = endPoint.Type.TryCreateListener( monitor, endPoint.TypedAddress );
            if( l != null )
            {
                l._transportManager = this;
                _listeners.Add( l );
            }
            return l;
        }

    }
}
