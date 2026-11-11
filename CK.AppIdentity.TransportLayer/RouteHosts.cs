using CK.Core;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// An authorized host of a route: the party <see cref="Host"/> may host the route <see cref="RouteName"/>, with the
/// <see cref="Target"/> (null when the route has none).
/// </summary>
/// <param name="RouteName">The name of the route.</param>
/// <param name="Host">The full name of the host.</param>
/// <param name="Target">The target of the route, null when it has none.</param>
public sealed record RouteHost( string RouteName, string Host, string? Target )
{
    /// <summary>
    /// Returns "RouteName: Host (Target)".
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => Target == null ? $"{RouteName}: {Host}" : $"{RouteName}: {Host} ({Target})";
}

/// <summary>
/// The hosts authorized for the routes of a local party (see <see cref="PartyRoute"/>): a route is accepted only when it
/// leads to an authorized host of its name, with exactly the authorized target. A route name can have several hosts.
/// <para>
/// They come from the <see cref="IRouteHostAuthority"/> (the Authentication Center of the party), otherwise from the
/// "RouteHosts" configuration of the local party (see <see cref="TryRead"/>). With neither, the routes are believed as
/// announced.
/// </para>
/// </summary>
public sealed class RouteHosts
{
    readonly ImmutableDictionary<(string Name, string Host), RouteHost> _entries;

    /// <summary>
    /// No authorized host: every route is refused.
    /// </summary>
    public static readonly RouteHosts Empty = new RouteHosts( ImmutableDictionary<(string, string), RouteHost>.Empty );

    RouteHosts( ImmutableDictionary<(string Name, string Host), RouteHost> entries ) => _entries = entries;

    /// <summary>
    /// Creates the authorized hosts. The same host of the same route twice is an error.
    /// </summary>
    /// <param name="entries">The authorized hosts.</param>
    /// <returns>The authorized hosts.</returns>
    public static RouteHosts Create( IEnumerable<RouteHost> entries )
    {
        Throw.CheckNotNullArgument( entries );
        var b = ImmutableDictionary.CreateBuilder<(string, string), RouteHost>();
        foreach( var e in entries )
        {
            Throw.CheckArgument( PartyDescription.IsValidName( e.RouteName ) && !string.IsNullOrWhiteSpace( e.Host ) );
            Throw.CheckArgument( $"The host '{e.Host}' of the route '{e.RouteName}' appears twice.", !b.ContainsKey( (e.RouteName, e.Host) ) );
            b.Add( (e.RouteName, e.Host), e );
        }
        return new RouteHosts( b.ToImmutable() );
    }

    /// <summary>
    /// Gets the authorized hosts.
    /// </summary>
    public IEnumerable<RouteHost> Entries => _entries.Values.OrderBy( e => e.RouteName, StringComparer.Ordinal ).ThenBy( e => e.Host, StringComparer.Ordinal );

    /// <summary>
    /// Finds the authorization of a host for a route name.
    /// </summary>
    /// <param name="routeName">The route name.</param>
    /// <param name="host">The full name of the host.</param>
    /// <returns>The authorization, or null.</returns>
    public RouteHost? Find( string routeName, string host ) => _entries.TryGetValue( (routeName, host), out var e ) ? e : null;

    /// <summary>
    /// Gets whether a route of a name is authorized: its host is an authorized host of the name, and its target is the
    /// authorized one.
    /// </summary>
    /// <param name="routeName">The route name.</param>
    /// <param name="route">The route.</param>
    /// <param name="reason">Why it is refused.</param>
    /// <returns>True when it is authorized.</returns>
    public bool IsAuthorized( string routeName, PartyRoute route, [NotNullWhen( false )] out string? reason )
    {
        var e = Find( routeName, route.Host );
        if( e == null )
        {
            reason = $"'{route.Host}' is not an authorized host of the route '{routeName}'";
            return false;
        }
        if( e.Target != route.Target )
        {
            reason = $"its target '{route.Target}' is not the authorized one ('{e.Target}')";
            return false;
        }
        reason = null;
        return true;
    }

    /// <summary>
    /// Reads the "RouteHosts" configuration of a local party: per route name, its hosts, a list of full names (the route
    /// has no target), or an object whose keys are the full names and the values their target.
    /// <code>
    /// "RouteHosts": {
    ///   "MailSender": [ "Acme/$Mail1", "Acme/$Mail2" ],
    ///   "Enlistment": { "Acme/$Admin": "https://admin.acme.com/app-identity/enlist" }
    /// }
    /// </code>
    /// </summary>
    /// <param name="monitor">The monitor that receives the errors.</param>
    /// <param name="section">The "RouteHosts" section, null when not configured.</param>
    /// <param name="hosts">The authorized hosts, null when not configured.</param>
    /// <returns>True on success, false on error.</returns>
    public static bool TryRead( IActivityMonitor monitor, ImmutableConfigurationSection? section, out RouteHosts? hosts )
    {
        hosts = null;
        if( section == null ) return true;
        var entries = new List<RouteHost>();
        bool success = true;
        foreach( var route in section.GetChildren() )
        {
            var name = route.Key;
            if( !PartyDescription.IsValidName( name ) )
            {
                monitor.Error( $"Invalid route name '{name}' in '{section.Path}'." );
                success = false;
                continue;
            }
            if( route.Value != null )
            {
                foreach( var h in route.Value.Split( ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries ) )
                {
                    entries.Add( new RouteHost( name, h, null ) );
                }
                continue;
            }
            foreach( var item in route.GetChildren() )
            {
                // An array (its keys are indexes): the hosts. An object: the hosts and their target.
                bool isIndex = item.Key.All( char.IsAsciiDigit );
                var host = isIndex ? item.Value : item.Key;
                var target = isIndex ? null : item.Value;
                if( string.IsNullOrWhiteSpace( host ) || (!isIndex && string.IsNullOrWhiteSpace( target )) )
                {
                    monitor.Error( $"Invalid host of the route '{name}' in '{item.Path}': a full name (and its target) is expected." );
                    success = false;
                    continue;
                }
                entries.Add( new RouteHost( name, host, target ) );
            }
        }
        var duplicate = entries.GroupBy( e => (e.RouteName, e.Host) ).FirstOrDefault( g => g.Count() > 1 );
        if( duplicate != null )
        {
            monitor.Error( $"The host '{duplicate.Key.Host}' of the route '{duplicate.Key.RouteName}' appears twice in '{section.Path}'." );
            success = false;
        }
        if( success ) hosts = Create( entries );
        return success;
    }
}

/// <summary>
/// The authority of the routes of a local party: the hosts it authorizes (see <see cref="RouteHosts"/>). Implemented by
/// CK.AppIdentity.AuthCenter: the authority of a local party is its Authentication Center. When it changes the hosts of a
/// local party, it calls <see cref="TransportFeatureDriver.OnRouteHostsChangedAsync"/>: the routes are computed again.
/// </summary>
public interface IRouteHostAuthority : ISingletonAutoService
{
    /// <summary>
    /// Gets the hosts authorized for the routes of a local party, null when this authority doesn't rule them (the party has
    /// no Authentication Center): the "RouteHosts" configuration of the party applies then.
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <returns>The authorized hosts, or null.</returns>
    RouteHosts? GetRouteHosts( ILocalParty local );
}
