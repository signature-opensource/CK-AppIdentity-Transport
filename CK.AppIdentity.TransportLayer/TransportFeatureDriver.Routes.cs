using CK.Core;
using System;
using System.Collections.Concurrent;
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
    /// The fact of a client application that is an approval page (see <see cref="ClientApplicationDescription.Facts"/>):
    /// its value is the path of the page, after the URL of the client application ("app-identity/enlist").
    /// </summary>
    public const string EnlistmentFact = "Enlistment";

    // The configured "RouteHosts" of the local parties (null when not configured), read at their setup.
    readonly ConcurrentDictionary<string, RouteHosts?> _configuredRouteHosts = new( StringComparer.Ordinal );
    // The local parties whose routes are believed as announced (no authority, no configuration): warned once.
    readonly ConcurrentDictionary<string, bool> _believedWarned = new( StringComparer.Ordinal );
    // The last refusals reported for a route name of a local party: reported when they appear or change.
    readonly ConcurrentDictionary<(string Local, string Name), string> _routeRefusals = new();

    bool ReadConfiguredRouteHosts( IActivityMonitor monitor, IEnumerable<ILocalParty> locals )
    {
        bool success = true;
        foreach( var local in locals )
        {
            if( RouteHosts.TryRead( monitor, local.LocalConfiguration.Configuration.TryResolveSection( "RouteHosts" ), out var hosts ) )
            {
                _configuredRouteHosts[local.FullName] = hosts;
            }
            else success = false;
        }
        return success;
    }

    /// <summary>
    /// Gets the hosts authorized for the routes of a local party: the ones of the <see cref="IRouteHostAuthority"/> (its
    /// Authentication Center), otherwise its "RouteHosts" configuration (see <see cref="RouteHosts.TryRead"/>). Null when
    /// it has neither: its routes are believed as announced.
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <returns>The authorized hosts, or null.</returns>
    public RouteHosts? GetRouteHosts( ILocalParty local )
    {
        Throw.CheckNotNullArgument( local );
        return _routeHostAuthority?.GetRouteHosts( local ) ?? (_configuredRouteHosts.TryGetValue( local.FullName, out var configured ) ? configured : null);
    }

    /// <summary>
    /// Gets the "Enlistment" route of a local party (the approval page of its System, see <see cref="EnlistmentRouteName"/>):
    /// its own page when it hosts one, otherwise the nearest one (the shortest route, then the ordinal name of its host).
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <returns>The route, or null when the party knows no approval page.</returns>
    public static PartyRoute? GetEnlistmentRoute( ILocalParty local )
    {
        Throw.CheckNotNullArgument( local );
        return local.Description.Routes.TryGetValue( EnlistmentRouteName, out var routes )
                ? routes.OrderBy( r => r.Length ).ThenBy( r => r.Host, StringComparer.Ordinal ).First()
                : null;
    }

    /// <summary>
    /// Called by the <see cref="IRouteHostAuthority"/> when the hosts authorized for the routes of a local party changed:
    /// its routes are computed again.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="local">The local party.</param>
    /// <returns>The awaitable.</returns>
    public Task OnRouteHostsChangedAsync( IActivityMonitor monitor, ILocalParty local ) => OnDescriptionChangedAsync( monitor, local );

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
    /// remote of the System, the hosted route and, per authorized host (see <see cref="GetRouteHosts"/>), the best route
    /// of the remotes, extended with the local party. A route to a host that is not authorized is refused.
    /// </summary>
    /// <param name="party">The local party.</param>
    /// <param name="builder">The second phase of its description.</param>
    protected override void ContributeDerivedDescription( ILocalParty party, PartyDescription.DerivedBuilder builder )
    {
        string local = party.FullName;
        var hosted = new Dictionary<string, string?>( builder.HostedRoutes, StringComparer.Ordinal );
        var pageUrl = GetEnlistmentPageUrl( local, builder );
        if( pageUrl != null ) hosted[EnlistmentRouteName] = pageUrl;

        // The connected remotes of the System: the routes of the others don't count.
        var remotes = party.Remotes.Where( r => r.DomainName == party.DomainName
                                                && r.EnvironmentName == party.EnvironmentName
                                                && r.GetFeature<TransportFeature>()?.ConnectionAvailability == ConnectionAvailability.Connected )
                                   .ToList();
        var authorized = GetRouteHosts( party );
        if( authorized == null && remotes.Any( r => r.Description.Routes.Count > 0 ) && _believedWarned.TryAdd( local, true ) )
        {
            ActivityMonitor.StaticLogger.Warn( ActivityMonitor.Tags.SecurityCritical,
                                               $"'{local}' has no authority of its routes (no Authentication Center) and no \"RouteHosts\" configuration: " +
                                               $"the routes of its remotes are believed as announced." );
        }
        var names = new SortedSet<string>( hosted.Keys, StringComparer.Ordinal );
        foreach( var r in remotes ) names.UnionWith( r.Description.Routes.Keys );
        var keys = party.GetFeature<KeyManagement.ILocalKeys>();
        foreach( var name in names )
        {
            var accepted = new List<PartyRoute>();
            var refused = new List<string>();
            foreach( var r in remotes )
            {
                if( !r.Description.Routes.TryGetValue( name, out var routes ) ) continue;
                foreach( var route in routes )
                {
                    if( keys != null && route.Path.FirstOrDefault( keys.IsNameBanned ) is { } banned )
                    {
                        ActivityMonitor.StaticLogger.Warn( ActivityMonitor.Tags.SecurityCritical, $"Route '{name}' of '{r.FullName}' ignored by '{local}': it goes through '{banned}', a revoked party." );
                        continue;
                    }
                    if( !route.TryAccept( r.FullName, local, out var reason ) )
                    {
                        ActivityMonitor.StaticLogger.Trace( $"Route '{name}' of '{r.FullName}' ignored by '{local}': {reason}." );
                        continue;
                    }
                    if( authorized != null && !authorized.IsAuthorized( name, route, out reason ) )
                    {
                        refused.Add( $"'{r.FullName}' announces '{route}': {reason}" );
                        continue;
                    }
                    accepted.Add( route );
                }
            }
            ReportRefusedRoutes( local, name, refused );
            // The best route per host; the local party uses its own route when it hosts the name.
            var best = accepted.GroupBy( a => a.Host, StringComparer.Ordinal )
                               .Select( g => PartyRoute.SelectBest( g )!.Extend( local ) )
                               .ToList();
            if( hosted.TryGetValue( name, out var target ) ) best.Add( PartyRoute.Hosted( target, local ) );
            builder.SetRoutes( name, best );
        }
        CollectAlongRoutes( local, builder, remotes );
    }

    // A route to a host that is not authorized means that a party announces a route it has no right to: it is refused,
    // and reported once per change (not at each computation).
    void ReportRefusedRoutes( string local, string name, List<string> refused )
    {
        if( refused.Count == 0 )
        {
            _routeRefusals.TryRemove( (local, name), out _ );
            return;
        }
        var text = string.Join( "; ", refused );
        if( _routeRefusals.TryGetValue( (local, name), out var last ) && last == text ) return;
        _routeRefusals[(local, name)] = text;
        ActivityMonitor.StaticLogger.Warn( ActivityMonitor.Tags.SecurityCritical, $"Routes '{name}' refused by '{local}': {text}." );
    }

    /// <summary>
    /// Collects the items of each route of the local party (see <see cref="PartyDescription.Collected"/>): its own items
    /// (stated by the first phase) and the items announced by the connected remotes one of whose routes of the same name
    /// goes through it (their next hop is the local party), extended with the local party: the items travel toward every
    /// host of the name. A party without a route of this name collects nothing: there is nowhere to carry the items.
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
                if( r.Description.Routes.TryGetValue( name, out var routes )
                    && routes.Any( route => route.NextHop == local )
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
    /// <see cref="EnlistmentFact"/>, followed by the value of the fact (the path of the page: exactly one non empty value).
    /// A party without public URL hosts no page: never a URL that can't be reached.
    /// </summary>
    static string? GetEnlistmentPageUrl( string local, PartyDescription.DerivedBuilder builder )
    {
        if( builder.PublicUrl == null ) return null;
        var page = builder.ClientApplications.FirstOrDefault( c => c.Facts.Contains( EnlistmentFact ) );
        if( page == null ) return null;
        var values = page.Facts.Get( EnlistmentFact );
        if( values.Length != 1 || string.IsNullOrWhiteSpace( values[0] ) )
        {
            ActivityMonitor.StaticLogger.Error( $"The client application '{page.Name}' of '{local}' has the \"{EnlistmentFact}\" fact with " +
                                                $"{values.Length} value(s) ({page.Facts}): exactly one value, the path of the approval page, is expected. No approval page." );
            return null;
        }
        return builder.PublicUrl.GetLeftPart( UriPartial.Authority ) + page.RequestPath.TrimEnd( '/' ) + "/" + values[0].Trim( '/' );
    }
}
