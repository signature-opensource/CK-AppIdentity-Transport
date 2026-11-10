using CK.Core;
using System.Linq;
using System.Text;

namespace CK.AppIdentity.TransportLayer;


// Accessibility is stated on the other part only: a partial type takes the accessibility of any
// part that declares one, so writing "public" here alone would publish the whole surface.
sealed partial class TransportManager
{
    /// <summary>
    /// Gets the enlistment URL that a local party hands to a party that doesn't trust it yet (or that it doesn't know):
    /// the <see cref="PartyRoute.Target"/> of its "Enlistment" route (see <see cref="TransportFeatureDriver.EnlistmentRouteName"/>),
    /// derived from the System, never configured. Null when the local party knows no approval page.
    /// </summary>
    /// <para>
    /// The URL selects the pending approval of the party to approve on the approval page: <c>?party={its full name}</c>
    /// is appended (escaped). When the URL would be too long with it, it is sent without it.
    /// </para>
    /// <param name="local">The local party concerned (see <see cref="GetEnlistingLocalParty"/>).</param>
    /// <param name="partyFullName">The full name of the party to approve (the one that receives the URL).</param>
    /// <returns>The enlistment url or null.</returns>
    /// <remarks>
    /// This is reached for <c>PeeringIssueKind.IncomingUnknown</c>, i.e. for a peer we have never heard of, whose
    /// local party is selected by a domain name taken from that peer's own self-asserted message. So any stranger can
    /// probe which domain names exist here and read each one's enlistment URL. The name is charset-validated, so there
    /// is no injection vector - this is disclosure, and for enlistment it is the intent: the URL of an approval page is
    /// meant to be handed to an unauthenticated caller.
    /// </remarks>
    internal string? GetEnlistRemoteUrl( ILocalParty local, string partyFullName )
    {
        var u = local.Description.Routes.GetValueOrDefault( TransportFeatureDriver.EnlistmentRouteName )?.Target;
        if( u != null )
        {
            var withParty = u + (u.Contains( '?' ) ? '&' : '?') + "party=" + System.Uri.EscapeDataString( partyFullName );
            if( Encoding.UTF8.GetByteCount( withParty ) <= ZeroProtocol.MaxEnlistRemoteUrlLength ) u = withParty;
            else Logger.Warn( $"The enlistment URL of '{local.FullName}' for '{partyFullName}' is too long with the party: sent without it." );
        }
        // The URL travels inside messages whose maximum length is budgeted term by term (ZeroProtocol.FirstAnswerMaxLength).
        // Without a bound here a long or non-ASCII URL simply makes the reply exceed its budget and be dropped as Invalid -
        // the operator gets no enlistment link and no explanation. Refusing it at the source says why.
        if( u != null && Encoding.UTF8.GetByteCount( u ) > ZeroProtocol.MaxEnlistRemoteUrlLength )
        {
            Logger.Error( $"The enlistment URL of '{local.FullName}' has {Encoding.UTF8.GetByteCount( u )} bytes, " +
                          $"more than the {ZeroProtocol.MaxEnlistRemoteUrlLength} bytes that fit in a negotiation message. Ignored." );
            return null;
        }
        return u;
    }

    /// <summary>
    /// Gets the local party concerned by a caller: the owner of the remote when it is known, otherwise the tenant domain
    /// whose domain name the caller claims, otherwise the root.
    /// </summary>
    /// <param name="party">The remote party if we already know it.</param>
    /// <param name="domainName">The domain name the caller claims.</param>
    /// <returns>The local party.</returns>
    internal ILocalParty GetEnlistingLocalParty( IRemoteParty? party, string domainName )
    {
        return party?.Owner
               ?? _agent.ApplicationIdentityService.TenantDomains.FirstOrDefault( d => d.DomainName == domainName )
               ?? (ILocalParty)_agent.ApplicationIdentityService;
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
