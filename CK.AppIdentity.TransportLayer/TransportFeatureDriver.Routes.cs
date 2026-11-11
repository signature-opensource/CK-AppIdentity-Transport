using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The routes of the local parties (see <see cref="PartyRoute"/>): the transport layer knows which remotes are connected,
/// so it computes, in the second phase of the description of each local party, the route of every name hosted here or
/// announced by a connected remote of the System. It also hosts the "Enlistment" route: the approval page of the System.
/// </summary>
public partial class TransportFeatureDriver
{
    /// <summary>
    /// The name of the route to the approval page of the System (see <see cref="PartyDescription.Routes"/>): its target is
    /// the URL of the page, handed to the parties that must be approved (the enlistment URL).
    /// </summary>
    public const string EnlistmentRouteName = "Enlistment";

    /// <summary>
    /// The fact of a client application that is an approval page (see <see cref="ClientApplicationDescription.Facts"/>).
    /// </summary>
    public const string EnlistmentFact = "Enlistment";

    /// <summary>
    /// The suffix of the URL of the approval page, after the URL of its client application.
    /// </summary>
    public const string EnlistmentPageSuffix = "/app-identity/enlist";

    void SubscribeRoutes( ILocalParty local ) => local.RemoteDescriptionChanged.Async += OnRemoteDescriptionChangedAsync;

    void UnsubscribeRoutes( ILocalParty local ) => local.RemoteDescriptionChanged.Async -= OnRemoteDescriptionChangedAsync;

    // A remote announced another description: its routes may have changed.
    Task OnRemoteDescriptionChangedAsync( IActivityMonitor monitor, IRemoteParty remote, CancellationToken cancel )
    {
        return OnDescriptionChangedAsync( monitor, remote.Owner );
    }

    // A remote connects or disconnects: its routes count or not.
    Task OnConnectionAvailabilityChangedAsync( IActivityMonitor monitor, TransportFeature transport, CancellationToken cancel )
    {
        return OnDescriptionChangedAsync( monitor, transport.Party.Owner );
    }

    /// <summary>
    /// Computes the routes of the local party: for each route name hosted here (the hosted routes of the first phase, and
    /// the "Enlistment" route when a client application has the <see cref="EnlistmentFact"/>) or announced by a connected
    /// remote of the System, the hosted route, or the best route of the remotes, extended with the local party.
    /// </summary>
    /// <param name="party">The local party.</param>
    /// <param name="builder">The second phase of its description.</param>
    protected override void ContributeDerivedDescription( ILocalParty party, PartyDescription.DerivedBuilder builder )
    {
        string local = party.FullName;
        var hosted = new Dictionary<string, string>( builder.HostedRoutes, StringComparer.Ordinal );
        var pageUrl = GetEnlistmentPageUrl( builder );
        if( pageUrl != null ) hosted[EnlistmentRouteName] = pageUrl;

        // The connected remotes of the System: the routes of the others don't count.
        var remotes = party.Remotes.Where( r => r.DomainName == party.DomainName
                                                && r.EnvironmentName == party.EnvironmentName
                                                && r.GetFeature<TransportFeature>()?.ConnectionAvailability == ConnectionAvailability.Connected )
                                   .ToList();
        var names = new SortedSet<string>( hosted.Keys, StringComparer.Ordinal );
        foreach( var r in remotes ) names.UnionWith( r.Description.Routes.Keys );
        var keys = party.GetFeature<KeyManagement.ILocalKeys>();
        foreach( var name in names )
        {
            var accepted = new List<PartyRoute>();
            foreach( var r in remotes )
            {
                if( r.Description.Routes.TryGetValue( name, out var route ) )
                {
                    if( keys != null && route.Path.FirstOrDefault( keys.IsNameBanned ) is { } banned )
                    {
                        ActivityMonitor.StaticLogger.Warn( ActivityMonitor.Tags.SecurityCritical, $"Route '{name}' of '{r.FullName}' ignored by '{local}': it goes through '{banned}', a revoked party." );
                        continue;
                    }
                    if( route.TryAccept( r.FullName, local, out var reason ) ) accepted.Add( route );
                    else ActivityMonitor.StaticLogger.Trace( $"Route '{name}' of '{r.FullName}' ignored by '{local}': {reason}." );
                }
            }
            bool isHosted = hosted.TryGetValue( name, out var target );
            CheckRouteHosts( local, name, isHosted, accepted );
            builder.SetRoute( name, isHosted ? PartyRoute.Hosted( target!, local ) : PartyRoute.SelectBest( accepted )?.Extend( local ) );
        }
        CollectAlongRoutes( local, builder, remotes );
    }

    // The last conflict reported for a route name of a local party: a conflict is reported when it appears or changes.
    readonly System.Collections.Concurrent.ConcurrentDictionary<(string Local, string Name), string> _routeConflicts = new();

    // A route name has one host: two hosts (announced by the remotes, or one of them and the local party) mean that a
    // party announces a route it doesn't host. The routed commands are safe (they name their destination, and every hop
    // checks it), but the conflict is reported: it is not silent.
    void CheckRouteHosts( string local, string name, bool isHosted, List<PartyRoute> accepted )
    {
        var hosts = accepted.Select( r => r.Host );
        if( isHosted ) hosts = hosts.Append( local );
        var distinct = hosts.Distinct( StringComparer.Ordinal ).Order( StringComparer.Ordinal ).ToList();
        if( distinct.Count <= 1 )
        {
            _routeConflicts.TryRemove( (local, name), out _ );
            return;
        }
        var announcers = string.Join( ", ", accepted.Select( r => $"'{r.Announcer}' (to '{r.Host}')" ) );
        var conflict = $"{string.Join( ", ", distinct.Select( h => $"'{h}'" ) )} by {announcers}";
        if( _routeConflicts.TryGetValue( (local, name), out var last ) && last == conflict ) return;
        _routeConflicts[(local, name)] = conflict;
        ActivityMonitor.StaticLogger.Warn( ActivityMonitor.Tags.SecurityCritical,
                                           $"The route '{name}' has more than one host for '{local}'{(isHosted ? " (that hosts it)" : "")}: {conflict}. A party announces a route it doesn't host." );
    }

    /// <summary>
    /// Collects the items of each route of the local party (see <see cref="PartyDescription.Collected"/>): its own items
    /// (stated by the first phase) and the items announced by the connected remotes whose route of the same name goes
    /// through it (their next hop is the local party), extended with the local party. A party without a route of this
    /// name collects nothing: there is nowhere to carry the items.
    /// </summary>
    static void CollectAlongRoutes( string local, PartyDescription.DerivedBuilder builder, List<IRemoteParty> remotes )
    {
        var names = new SortedSet<string>( builder.OwnCollected.Keys, StringComparer.Ordinal );
        foreach( var r in remotes ) names.UnionWith( r.Description.Collected.Keys );
        foreach( var name in names )
        {
            if( !builder.Routes.ContainsKey( name ) )
            {
                if( builder.OwnCollected.ContainsKey( name ) )
                {
                    ActivityMonitor.StaticLogger.Trace( $"'{local}' has items to collect along the route '{name}' but no such route." );
                }
                continue;
            }
            var own = builder.OwnCollected.TryGetValue( name, out var values )
                        ? values.Select( v => CollectedItem.Own( v, local ) )
                        : [];
            var received = new List<CollectedItem>();
            foreach( var r in remotes )
            {
                if( r.Description.Routes.TryGetValue( name, out var route )
                    && route.NextHop == local
                    && r.Description.Collected.TryGetValue( name, out var items ) )
                {
                    foreach( var item in items )
                    {
                        if( item.TryAccept( r.FullName, local, out var reason ) ) received.Add( item.Extend( local ) );
                        else ActivityMonitor.StaticLogger.Trace( $"Item '{item}' collected along '{name}' by '{r.FullName}' ignored by '{local}': {reason}." );
                    }
                }
            }
            // The own items first, then the nearest ones: an item found twice keeps its shortest path, and the bound
            // drops the farthest items.
            var kept = new List<CollectedItem>();
            int dropped = 0;
            foreach( var item in own.Concat( received.OrderBy( i => i.Length ).ThenBy( i => i, CollectedItem.Comparer ) ) )
            {
                if( kept.Any( k => k.IsSameItem( item ) ) ) continue;
                if( kept.Count == CollectedItem.MaxCount ) ++dropped;
                else kept.Add( item );
            }
            if( dropped > 0 )
            {
                ActivityMonitor.StaticLogger.Warn( $"'{local}' collects at most {CollectedItem.MaxCount} items along the route '{name}': {dropped} item(s) dropped." );
            }
            builder.SetCollected( name, kept );
        }
    }

    /// <summary>
    /// Gets the URL of the approval page of the party, or null: the URL of its client application that has the
    /// <see cref="EnlistmentFact"/>, followed by the <see cref="EnlistmentPageSuffix"/>. A party without public URL hosts
    /// no page: never a URL that can't be reached.
    /// </summary>
    static string? GetEnlistmentPageUrl( PartyDescription.DerivedBuilder builder )
    {
        if( builder.PublicUrl == null ) return null;
        var fact = ClientApplicationDescription.FactContext.FindOrCreate( EnlistmentFact );
        var page = builder.ClientApplications.FirstOrDefault( c => c.Facts.IsSupersetOf( fact ) );
        return page != null
                ? builder.PublicUrl.GetLeftPart( UriPartial.Authority ) + page.RequestPath.TrimEnd( '/' ) + EnlistmentPageSuffix
                : null;
    }
}
