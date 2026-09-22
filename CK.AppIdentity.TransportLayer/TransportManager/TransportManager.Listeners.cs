using CK.Core;
using System.Linq;
using System.Text;

namespace CK.AppIdentity.TransportLayer;


// Accessibility is stated on the other part only: a partial type takes the accessibility of any
// part that declares one, so writing "public" here alone would publish the whole surface.
sealed partial class TransportManager
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
    /// <returns>The enlistment url or null.</returns>
    /// <remarks>
    /// This is reached for <c>PeeringIssueKind.IncomingUnknown</c>, i.e. for a peer we have never
    /// heard of, and it selects the tenant by a domain name taken from that peer's own self-asserted
    /// message. So any stranger can probe which domain names exist here and read each one's
    /// "EnlistRemoteUrl". The name is charset-validated, so there is no injection vector - this is
    /// disclosure, and for enlistment it is very likely the intent. Do not put anything in
    /// "EnlistRemoteUrl" that is not meant to be handed to an unauthenticated caller.
    /// </remarks>
    internal string? GetEnlistRemoteUrl( IRemoteParty? party, string domainName )
    {
        IParty? closest = party;
        closest ??= _agent.ApplicationIdentityService.TenantDomains.FirstOrDefault( d => d.DomainName == domainName );
        var u = closest?.Configuration.Configuration.TryLookupValue( "EnlistRemoteUrl" );
        if( u != null ) u = u.Replace( "{DomainName}", domainName );
        // The value is raw configuration and travels inside messages whose maximum length is budgeted
        // term by term (ZeroProtocol.FirstAnswerMaxLength). Without a bound here a long or non-ASCII
        // URL simply makes the reply exceed its budget and be dropped as Invalid - the operator gets
        // no enlistment link and no explanation. Refusing it at the source says why.
        if( u != null && Encoding.UTF8.GetByteCount( u ) > ZeroProtocol.MaxEnlistRemoteUrlLength )
        {
            Logger.Error( $"'EnlistRemoteUrl' resolves to {Encoding.UTF8.GetByteCount( u )} bytes, " +
                          $"more than the {ZeroProtocol.MaxEnlistRemoteUrlLength} bytes that fit in a negotiation message. Ignored." );
            return null;
        }
        return u;
    }

    /// <summary>
    /// Ensures that a listener is setup on the <paramref name="endPoint"/>.
    /// The listener should be as ready as possible to handle incoming connections
    /// (even if it has no parties registered at the start).
    /// <para>
    /// We want this to be called before starting anything as a configuration validation
    /// (this is called by TransportFeatureDriver.SetupAsync and SetupDynamicRemoteAsync).
    /// There is NO concurrent calls to TryEnsureListener/OnListenerDisposed.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to signal errors.</param>
    /// <param name="endPoint">The listening address.</param>
    /// <returns>The listener on success, null otherwise.</returns>
    internal TransportListener? TryEnsureListener( IActivityMonitor monitor, TransportTypeAddress endPoint )
    {
        Throw.DebugAssert( IsInApplicationIdentityLoop( monitor ) );

        foreach( var exists in _listeners )
        {
            if( exists.IsListeningAddress( endPoint ) )
            {
                exists.AddRef( monitor );
                return exists;
            }
        }
        var l = endPoint.Type.TryCreateListener( monitor, this, endPoint.TypedAddress );
        if( l != null )
        {
            _listeners.Add( l );
            // A party with no ListeningAddress anywhere binds 0.0.0.0. Combined with AutoTrustKey
            // that is the widest default exposure in the stack, and Trace is not where an operator
            // looks for it.
            if( endPoint.TypedAddress is System.Net.IPEndPoint ip && ip.Address.Equals( System.Net.IPAddress.Any ) )
            {
                monitor.Warn( $"Created listener '{l}': bound on ALL interfaces." );
            }
            else
            {
                monitor.Trace( $"Created listener '{l}'." );
            }
        }
        return l;
    }

    internal void OnListenerDisposed( IActivityMonitor monitor, TransportListener listener )
    {
        Throw.DebugAssert( IsInApplicationIdentityLoop( monitor ) );
        _listeners.Remove( listener );
    }
}
