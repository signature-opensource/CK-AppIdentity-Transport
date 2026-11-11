using CK.AppIdentity.KeyManagement;
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
        var u = TransportFeatureDriver.GetEnlistmentRoute( local )?.Target;
        if( u != null )
        {
            u = AppendParty( u, partyFullName, local.FullName );
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

    // Appends "?party={partyFullName}" (escaped) to the URL of an approval page, when it fits.
    string AppendParty( string u, string partyFullName, string urlOwner )
    {
        var withParty = u + (u.Contains( '?' ) ? '&' : '?') + "party=" + System.Uri.EscapeDataString( partyFullName );
        if( Encoding.UTF8.GetByteCount( withParty ) <= ZeroProtocol.MaxEnlistRemoteUrlLength ) return withParty;
        Logger.Warn( $"The enlistment URL of '{urlOwner}' for '{partyFullName}' is too long with the party: used without it." );
        return u;
    }

    /// <summary>
    /// Gets the enlistment URL that a local party hands over: the <see cref="EnlistmentUrlStatement"/> of the authority of
    /// its System (<see cref="IPeeringAuthority"/>) when it states the target of its "Enlistment" route (the receiver
    /// appends <c>?party=</c>), otherwise the bare URL (see <see cref="GetEnlistRemoteUrl"/>).
    /// </summary>
    /// <param name="local">The local party concerned.</param>
    /// <param name="partyFullName">The full name of the party to approve (the one that receives the URL).</param>
    /// <returns>The bare URL or the statement (or none).</returns>
    internal (string? Url, AnchoredStatement? Statement) GetEnlistUrlToSend( ILocalParty local, string partyFullName )
    {
        var s = _peeringAuthority?.GetEnlistmentUrl( local );
        if( s != null && s.Expiration > SystemClock.UtcNow )
        {
            var u = EnlistmentUrlStatement.TryRead( s );
            if( u != null && u == TransportFeatureDriver.GetEnlistmentRoute( local )?.Target )
            {
                return (null, s);
            }
        }
        return (GetEnlistRemoteUrl( local, partyFullName ), null);
    }

    /// <summary>
    /// Reads the enlistment URL received by a local party: the bare one, or the one of an <see cref="EnlistmentUrlStatement"/>
    /// (with <c>?party={receiver}</c> appended). The URL of a statement that verifies with the keys of the authority of the
    /// receiver is authenticated, whatever the path and whoever sent it.
    /// </summary>
    /// <param name="receiver">The local party that receives the URL.</param>
    /// <param name="url">The bare URL.</param>
    /// <param name="statement">The statement.</param>
    /// <param name="isAuthenticated">Whether the URL is authenticated: set to true when the statement verifies.</param>
    /// <returns>The URL, null when none.</returns>
    internal string? ReadReceivedEnlistUrl( ILocalParty receiver, string? url, AnchoredStatement? statement, ref bool isAuthenticated )
    {
        if( statement == null ) return url;
        var u = EnlistmentUrlStatement.TryRead( statement );
        if( u == null )
        {
            Logger.Warn( $"'{receiver}' received a {statement} instead of an enlistment URL: ignored." );
            return url;
        }
        if( VerifyAuthorityStatement( receiver, statement, EnlistmentUrlStatement.Purpose ) )
        {
            isAuthenticated = true;
        }
        return AppendParty( u, receiver.FullName, statement.SignerFullName );
    }

    /// <summary>
    /// Verifies a statement of the authority of a local party (<see cref="IPeeringAuthority.GetAuthority"/>) with the keys
    /// the local party holds of it (its trust anchor, or its pin when it is a remote).
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <param name="statement">The statement.</param>
    /// <param name="purpose">The expected purpose.</param>
    /// <returns>True when the statement is the authority's.</returns>
    internal bool VerifyAuthorityStatement( ILocalParty local, AnchoredStatement statement, string purpose )
    {
        var authority = _peeringAuthority?.GetAuthority( local );
        if( authority == null )
        {
            Logger.Trace( $"'{local}' has no authority: the {statement} is not verified." );
            return false;
        }
        if( statement.SignerFullName != authority )
        {
            Logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{local}' refuses the {statement}: it is not signed by its authority '{authority}'." );
            return false;
        }
        var keys = local.GetFeature<ILocalKeys>();
        if( keys == null ) return false;
        var verdict = statement.Verify( Logger, keys, purpose );
        if( verdict != SignatureVerdict.Valid )
        {
            Logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{local}' refuses the {statement}: {verdict}." );
            return false;
        }
        return true;
    }

    /// <summary>
    /// On the waiting party: pins a remote from a <see cref="PinGrant"/> it handed over. The grant must name the local
    /// party, its current key (or the key of one of its last events), and the remote; it must verify with the keys of the
    /// authority; the events the remote presented must verify from the checkpoint of the grant.
    /// </summary>
    /// <param name="remote">The remote that sent the grant (the holder).</param>
    /// <param name="grant">The grant.</param>
    /// <param name="block">The identity block the remote sent with it.</param>
    /// <returns>True when the remote is pinned.</returns>
    internal bool TryPinFromGrant( TransportFeature remote, AnchoredStatement grant, in IdentityBlock block )
    {
        var local = remote.Party.Owner;
        if( !PinGrant.TryRead( grant, out var waiting, out var fingerprint, out var holder, out var checkpoint ) )
        {
            Logger.Warn( $"'{remote.Party}' sent a {grant} that is not a pin grant: ignored." );
            return false;
        }
        if( waiting != local.FullName.Path || holder != remote.Party.FullName.Path )
        {
            Logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{remote.Party}' sent a pin grant of '{waiting}' for '{holder}' to '{local}': ignored." );
            return false;
        }
        var keys = local.GetFeature<ILocalKeys>();
        if( keys == null || !keys.State.Tail.Any( e => new RemoteIdentityKeyData( e ).GetFingerprint() == fingerprint ) )
        {
            Logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{remote.Party}' sent a pin grant for the key '{fingerprint}' of '{local}': it is not its key. Ignored." );
            return false;
        }
        if( !VerifyAuthorityStatement( local, grant, PinGrant.Purpose ) ) return false;
        if( !remote.RemoteKeys.PinFromCheckpoint( Logger, block.Tail, checkpoint! ) ) return false;
        Logger.Info( ActivityMonitor.Tags.SecurityCritical,
                     $"'{local}' pinned '{remote.Party}' (#{block.Head.Seq}) from the pin grant of its authority '{grant.SignerFullName}' (checkpoint {checkpoint})." );
        return true;
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
