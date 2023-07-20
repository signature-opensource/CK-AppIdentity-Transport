using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{

    public sealed partial class TransportManager
    {
        /// <summary>
        /// Tries to return the configured "EnlistRemoteUrl" that can be displayed on a remote and can be
        /// used to enlist a not yet known remote into one of our local parties.
        /// If the IRemoteParty has been found (we have it, it's its TrustedIdentity that is missing), we use
        /// its Owner local to find the "closest" url pattern.
        /// If the IRemoteParty is null, we use the DomainName to try to locate a domain that would better host
        /// this remote than the Local one.
        /// </summary>
        /// <param name="party">The remote party if we already know it.</param>
        /// <param name="domainName">The domain name of the remote.</param>
        /// <returns></returns>
        internal string? GetEnlistRemoteUrl( IRemoteParty? party, string domainName )
        {
            IParty? closest = party;
            closest ??= _agent.ApplicationIdentityService.TenantDomains.FirstOrDefault( d => d.DomainName == domainName );
            var u = closest?.Configuration.Configuration.TryLookupValue( "EnlistRemoteUrl" );
            if( u != null ) u = u.Replace( "{DomainName}", domainName );
            return u;
        }


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
