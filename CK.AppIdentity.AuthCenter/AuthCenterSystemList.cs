using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The System list of a local party that has an Authentication Center (a feature of the local party, see
/// <see cref="SystemList"/>): the newest list it verified. It is kept in its local store, applied to its keys (see
/// <see cref="ILocalKeys.SetRevocationsAsync"/>: the revoked remotes are cut) and relayed to its remotes of the System:
/// when a channel becomes available, and when a newer list is adopted (from any remote: <see cref="ISystemListCommand"/>).
/// <para>
/// Its <see cref="RouteHosts"/> are the hosts authorized for the routes of the local party (see
/// <see cref="AuthCenterRouteHostAuthority"/>): the ones of the list, and the Authentication Center for its own
/// "AuthCenter" route (implicit: the list itself is pulled along it). Before any list, only this route is authorized.
/// </para>
/// <para>
/// A list is adopted only when its sequence number is greater than the one held and when its signature is the
/// Authentication Center's (verified with its keys, pinned or anchored): a hop can withhold a list, not forge one.
/// </para>
/// <para>
/// The freshness: a party that is not the Authentication Center also asks it its current list every
/// <see cref="PullPeriod"/> (on the channel or along its route: <see cref="IGetSystemListQCommand"/>), and raises a
/// <see cref="ActivityMonitor.Tags.SecurityCritical"/> alarm when the signature of the list it holds expired (the
/// Authentication Center signs it again before: an expired one means that nothing newer reached this party).
/// </para>
/// </summary>
public sealed class AuthCenterSystemList
{
    /// <summary>
    /// The name of the file of the list, in the local store of the local party.
    /// </summary>
    public const string FileName = "SystemList.bin";

    /// <summary>
    /// The period of the pull of the current list from the Authentication Center: 1 hour.
    /// </summary>
    public static readonly TimeSpan PullPeriod = TimeSpan.FromHours( 1 );

    readonly CrisAuthCenter _center;
    readonly SemaphoreSlim _adoptLock;
    // On the Authentication Center: serializes the signing of the lists (read the current one, compute, sign, adopt).
    readonly SemaphoreSlim _updateLock;
    readonly Func<IActivityMonitor, Task<object?>>? _pull;
    readonly Func<IActivityMonitor, Task>? _onRouteHostsChanged;
    SystemList? _current;
    RouteHosts _routeHosts;
    // The stored list whose signer is not known yet at setup: verified (with the key events) by the first heartbeat.
    byte[]? _stored;
    TransportManagerFeature? _transport;
    DateTime _nextPull;
    int _pulling;
    bool _detached;
    readonly object _detachLock = new object();


    AuthCenterSystemList( CrisAuthCenter center, Func<IActivityMonitor, Task<object?>>? pull, Func<IActivityMonitor, Task>? onRouteHostsChanged )
    {
        _center = center;
        _pull = pull;
        _onRouteHostsChanged = onRouteHostsChanged;
        _adoptLock = new SemaphoreSlim( 1, 1 );
        _updateLock = new SemaphoreSlim( 1, 1 );
        _routeHosts = GetRouteHosts( center, null );
    }

    /// <summary>
    /// Gets the newest list verified here, null when none.
    /// </summary>
    public SystemList? Current => _current;

    /// <summary>
    /// Gets the hosts authorized for the routes of the local party: the ones of the <see cref="Current"/> list, and the
    /// Authentication Center for its "AuthCenter" route.
    /// </summary>
    public RouteHosts RouteHosts => _routeHosts;

    /// <summary>
    /// Gets the callback of <see cref="Plug"/> that has the transport compute the routes of a local party again (nothing
    /// when there is no transport).
    /// </summary>
    /// <param name="services">The root services.</param>
    /// <param name="local">The local party.</param>
    /// <returns>The callback.</returns>
    public static Func<IActivityMonitor, Task> OnRouteHostsChanged( IServiceProvider services, ILocalParty local )
    {
        Throw.CheckNotNullArgument( services );
        Throw.CheckNotNullArgument( local );
        return m => services.GetService( typeof( TransportFeatureDriver ) ) is TransportFeatureDriver t
                        ? t.OnRouteHostsChangedAsync( m, local )
                        : Task.CompletedTask;
    }

    /// <summary>
    /// Finds the target of a route that a host announces, when the local party sees the host's description: the host is
    /// the local party itself, or one of its remotes.
    /// </summary>
    /// <param name="local">The local party (the Authentication Center).</param>
    /// <param name="routeName">The route name.</param>
    /// <param name="host">The full name of the host.</param>
    /// <param name="seen">True when the host's description is seen and announces the route.</param>
    /// <returns>The target (null when the route has none, or is not seen).</returns>
    public static string? FindAnnouncedTarget( ILocalParty local, string routeName, string host, out bool seen )
    {
        Throw.CheckNotNullArgument( local );
        var description = host == local.FullName.Path
                            ? local.Description
                            : local.Remotes.FirstOrDefault( r => r.FullName.Path == host )?.Description;
        var route = description?.FindRoute( routeName, host );
        seen = route != null;
        return route?.Target;
    }

    /// <summary>
    /// On the Authentication Center: authorizes a host for routes (the ones it doesn't host yet), with the target it
    /// announces when it is seen (see <see cref="FindAnnouncedTarget"/>; the Authentication Center keeps it up to date).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="host">The full name of the host.</param>
    /// <param name="routeNames">The route names.</param>
    /// <returns>The list.</returns>
    public Task<SystemList?> AuthorizeAsync( IActivityMonitor monitor, string host, IEnumerable<string> routeNames )
    {
        Throw.CheckNotNullArgument( host );
        Throw.CheckNotNullArgument( routeNames );
        var names = routeNames.Where( n => PartyDescription.IsValidName( n ) && n != AuthCenterFeature.RouteName ).Distinct( StringComparer.Ordinal ).ToList();
        return UpdateAsync( monitor, ( entries, hosts ) =>
        {
            var h = hosts.ToList();
            foreach( var name in names )
            {
                if( !h.Any( x => x.RouteName == name && x.Host == host ) )
                {
                    h.Add( new RouteHost( name, host, FindAnnouncedTarget( Local, name, host, out _ ) ) );
                }
            }
            return (entries, h);
        } );
    }

    static RouteHosts GetRouteHosts( CrisAuthCenter center, SystemList? list )
    {
        var implicitHost = new RouteHost( AuthCenterFeature.RouteName, center.AuthCenterFullName, null );
        return RouteHosts.Create( (list?.RouteHosts ?? []).Where( h => h.RouteName != AuthCenterFeature.RouteName ).Append( implicitHost ) );
    }

    /// <summary>
    /// Gets the Authentication Center.
    /// </summary>
    public CrisAuthCenter Center => _center;

    ILocalParty Local => _center.Owner;

    NormalizedPath FilePath => StoreFilePath( Local );


    /// <summary>
    /// Creates the feature of a local party once its <see cref="CrisAuthCenter"/> exists (used by the two sides of the
    /// "AuthCenter" feature). The list kept in its local store is verified again with the keys of the Authentication Center
    /// (it may have changed since: a reconfigured or re-incepted Authentication Center) and applied to its keys. When its
    /// signer is not known here yet, it is verified by the first heartbeat (the key events of the Authentication Center are
    /// then obtained); a list that is not signed by the Authentication Center is ignored.
    /// <para>
    /// The feature follows the heartbeat: a party that is not the Authentication Center pulls the list, the Authentication
    /// Center signs it again before its signature expires (see <see cref="RenewIfNeededAsync"/>). <see cref="Detach"/> ends this.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="center">The Authentication Center of the local party.</param>
    /// <param name="pull">
    /// Sends an <see cref="IGetSystemListQCommand"/> to the Authentication Center and returns its result (null for the
    /// Authentication Center itself): the periodic pull.
    /// </param>
    /// <param name="onRouteHostsChanged">
    /// Called when the <see cref="RouteHosts"/> changed (the transport computes the routes of the local party again).
    /// </param>
    /// <returns>The feature.</returns>
    public static async Task<AuthCenterSystemList> PlugAsync( IActivityMonitor monitor,
                                                              CrisAuthCenter center,
                                                              Func<IActivityMonitor, Task<object?>>? pull,
                                                              Func<IActivityMonitor, Task>? onRouteHostsChanged )
    {
        var local = center.Owner;
        var f = await CreateAsync( monitor, center, pull, onRouteHostsChanged, local.LocalFileStore.TryReadAllBytes( StoreFilePath( local ) ) ).ConfigureAwait( false );
        local.AddFeature( f );
        local.ApplicationIdentityService.Heartbeat.Async += f.OnHeartbeatAsync;
        // The transport exists once the initialization is done: the list is then sent when a channel becomes available.
        _ = local.ApplicationIdentityService.InitializationTask.ContinueWith( _ =>
        {
            if( local.ApplicationIdentityService.GetFeature<TransportManagerFeature>() is { } transport )
            {
                lock( f._detachLock )
                {
                    if( f._detached ) return;
                    f._transport = transport;
                    transport.ConnectionAvailabilityChanged.Async += f.OnConnectionAvailabilityChangedAsync;
                }
            }
        }, TaskScheduler.Default );
        return f;
    }

    static NormalizedPath StoreFilePath( ILocalParty local ) => local.LocalFileStore.FolderPath.AppendPart( FileName );

    // Creates the feature with the list read from the store (null when there is none).
    internal static async Task<AuthCenterSystemList> CreateAsync( IActivityMonitor monitor,
                                                                  CrisAuthCenter center,
                                                                  Func<IActivityMonitor, Task<object?>>? pull,
                                                                  Func<IActivityMonitor, Task>? onRouteHostsChanged,
                                                                  byte[]? bytes )
    {
        var f = new AuthCenterSystemList( center, pull, onRouteHostsChanged );
        var local = center.Owner;
        if( bytes != null )
        {
            if( SystemList.TryDecode( bytes, out var list ) && local.GetFeature<ILocalKeys>() is { } keys )
            {
                var verdict = center.CheckSignature( monitor, SystemList.Purpose, list!.SignedData, list.Signature );
                if( verdict == SignatureVerdict.Valid )
                {
                    f._current = list;
                    f._routeHosts = GetRouteHosts( center, list );
                    await keys.SetRevocationsAsync( monitor, list.Entries ).ConfigureAwait( false );
                    monitor.Info( $"{list} of '{local}' is loaded." );
                }
                else if( verdict == SignatureVerdict.UnknownIssuer )
                {
                    f._stored = bytes;
                    monitor.Info( $"The {list} stored by '{local}' is signed by a key of the AuthCenter '{center.AuthCenterFullName}' that is not known yet: it will be verified with its key events." );
                }
                else
                {
                    monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The {list} stored by '{local}' is not signed by its AuthCenter '{center.AuthCenterFullName}' ({verdict}): it is ignored." );
                }
            }
            else
            {
                monitor.Error( $"The System list stored by '{local}' can't be read: it will be received again from its remotes." );
            }
        }
        return f;
    }

    /// <summary>
    /// Ends the subscriptions of this feature (the heartbeat, the transport): called by the drivers when its local party is
    /// destroyed (a dynamic tenant domain) or when the application stops.
    /// </summary>
    public void Detach()
    {
        Local.ApplicationIdentityService.Heartbeat.Async -= OnHeartbeatAsync;
        lock( _detachLock )
        {
            _detached = true;
            if( _transport != null ) _transport.ConnectionAvailabilityChanged.Async -= OnConnectionAvailabilityChangedAsync;
            _transport = null;
        }
    }

    // The heartbeat runs on the agent loop: the work runs in the background, every PullPeriod. A party that is not the
    // Authentication Center pulls the list and checks its staleness, the Authentication Center renews its list.
    Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount, CancellationToken cancel )
    {
        var utcNow = DateTime.UtcNow;
        if( utcNow >= _nextPull && Interlocked.CompareExchange( ref _pulling, 1, 0 ) == 0 )
        {
            _nextPull = utcNow + PullPeriod;
            _ = Task.Run( async () =>
            {
                var m = new ActivityMonitor( $"The System list of the AuthCenter of '{Local}'." );
                try
                {
                    if( Interlocked.Exchange( ref _stored, null ) is { } stored )
                    {
                        await TryAdoptAsync( m, stored, null ).ConfigureAwait( false );
                    }
                    if( _pull != null )
                    {
                        await PullAsync( m ).ConfigureAwait( false );
                        CheckStaleness( m, DateTime.UtcNow );
                    }
                    else
                    {
                        // The System list is signed again before its signature expires.
                        await RenewIfNeededAsync( m, DateTime.UtcNow ).ConfigureAwait( false );
                    }
                }
                catch( Exception ex )
                {
                    m.Error( _pull != null ? "While pulling the System list." : "While renewing the System list.", ex );
                }
                finally
                {
                    m.MonitorEnd();
                    _pulling = 0;
                }
            } );
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Asks the Authentication Center its current list and adopts it when it is newer (and verifies).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>True when a newer list has been adopted.</returns>
    public async Task<bool> PullAsync( IActivityMonitor monitor )
    {
        if( _pull == null ) return false;
        object? result;
        try
        {
            result = await _pull( monitor ).ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to ask the AuthCenter '{_center.AuthCenterFullName}' its System list.", ex );
            return false;
        }
        if( result is byte[] encoded )
        {
            // The AuthCenter answers its current list: an older one than the one held here means that it has been reset
            // (or replaced), the lists it signs are ignored until their sequence number passes the one held here.
            if( _current != null && SystemList.TryDecode( encoded, out var pulled ) && pulled!.Seq < _current.Seq )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The AuthCenter '{_center.AuthCenterFullName}' answers its {pulled}, older than the {_current} held by '{Local}': it is ignored." );
                return false;
            }
            return await TryAdoptAsync( monitor, encoded, null ).ConfigureAwait( false );
        }
        if( result != null ) monitor.Warn( $"The AuthCenter '{_center.AuthCenterFullName}' can't be asked its System list: {result}." );
        return false;
    }

    /// <summary>
    /// Raises the alarm when the signature of the list held expired: the Authentication Center signs it again before, so
    /// nothing newer reached this party (a hop withholds it, or the Authentication Center is unreachable).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>True when the list is stale.</returns>
    public bool CheckStaleness( IActivityMonitor monitor, DateTime utcNow )
    {
        var current = _current;
        if( current == null || current.Signature.Expiration > utcNow ) return false;
        monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                      $"The {current} held by '{Local}' is stale: its signature expired at {current.Signature.Expiration:O}, nothing newer reached it from the AuthCenter '{_center.AuthCenterFullName}'." );
        return true;
    }

    Task OnConnectionAvailabilityChangedAsync( IActivityMonitor monitor, TransportFeature transport, CancellationToken cancel )
    {
        if( _current != null
            && transport.ConnectionAvailability == ConnectionAvailability.Connected
            && transport.Party.Owner == Local
            && IsInSystem( transport.Party ) )
        {
            Send( monitor, transport.Party, _current );
        }
        return Task.CompletedTask;
    }

    bool IsInSystem( IRemoteParty r ) => r.DomainName == Local.DomainName && r.EnvironmentName == Local.EnvironmentName;

    void Send( IActivityMonitor monitor, IRemoteParty remote, SystemList list )
    {
        var channel = remote.GetFeature<CrisChannelFeature>();
        if( channel == null ) return;
        var command = channel.PocoDirectory.Create<ISystemListCommand>( c => c.Encoded = list.Encode() );
        channel.SendCommand( monitor, command );
        monitor.Trace( $"{list} sent to '{remote}'." );
    }

    /// <summary>
    /// On the Authentication Center: signs a new list (the next sequence number) with its revocations and its route hosts
    /// computed from the current ones, and adopts it (it is relayed to every party of the System). Nothing is signed when
    /// they don't change. The updates are serialized: <paramref name="update"/> always sees the list of the previous one.
    /// <para>
    /// A revoked party is no more an authorized host of any route: the route hosts whose name is banned by an entry of the
    /// new list are dropped, whatever <paramref name="update"/> returns.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="update">Computes the new revocations and route hosts from the current ones.</param>
    /// <returns>The new list, the current one when nothing changed (null when there is none).</returns>
    public async Task<SystemList?> UpdateAsync( IActivityMonitor monitor,
                                                Func<IReadOnlyList<RevocationEntry>, IReadOnlyList<RouteHost>, (IReadOnlyList<RevocationEntry> Entries, IReadOnlyList<RouteHost> RouteHosts)> update )
    {
        Throw.CheckState( "Only the Authentication Center signs its list.", _center.AuthCenter == Local );
        Throw.CheckNotNullArgument( update );
        await _updateLock.WaitAsync().ConfigureAwait( false );
        try
        {
            var current = _current;
            IReadOnlyList<RevocationEntry> entries = current?.Entries ?? [];
            IReadOnlyList<RouteHost> hosts = current?.RouteHosts ?? [];
            var (newEntries, newHosts) = update( entries, hosts );
            var banned = newEntries.Where( e => e.NameBanned ).Select( e => e.FullName ).ToHashSet( StringComparer.Ordinal );
            var sortedHosts = newHosts.Where( h => !banned.Contains( h.Host ) )
                                      .OrderBy( h => h.RouteName, StringComparer.Ordinal )
                                      .ThenBy( h => h.Host, StringComparer.Ordinal )
                                      .ToList();
            if( newEntries.SequenceEqual( entries ) && sortedHosts.SequenceEqual( hosts ) ) return current;
            var list = SystemList.Create( Local.GetRequiredFeature<ILocalKeys>(), (current?.Seq ?? 0) + 1, newEntries, sortedHosts, DateTime.UtcNow );
            return await AdoptOwnAsync( monitor, list ).ConfigureAwait( false );
        }
        finally
        {
            _updateLock.Release();
        }
    }

    // Adopts a list signed here (under the update lock): it can't be refused, a failure is an error, never a silent loss.
    async Task<SystemList> AdoptOwnAsync( IActivityMonitor monitor, SystemList list )
    {
        if( !await TryAdoptAsync( monitor, list.Encode(), null ).ConfigureAwait( false ) )
        {
            Throw.CKException( $"The {list} signed by the AuthCenter '{Local}' has not been adopted: its change is not applied." );
        }
        return list;
    }

    /// <summary>
    /// On the Authentication Center: signs its list again (the same entries, the next sequence number) when its signature
    /// reaches the middle of its life (a signature lasts at most <see cref="ILocalKeys.MaxSignatureDays"/>): the list stays
    /// verifiable by the parties that receive it later.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>True when a new list has been signed and adopted.</returns>
    public async Task<bool> RenewIfNeededAsync( IActivityMonitor monitor, DateTime utcNow )
    {
        Throw.CheckState( "Only the Authentication Center signs its list.", _center.AuthCenter == Local );
        await _updateLock.WaitAsync().ConfigureAwait( false );
        try
        {
            var current = _current;
            var keys = Local.GetRequiredFeature<ILocalKeys>();
            if( current == null || current.Signature.Expiration - utcNow > TimeSpan.FromDays( keys.MaxSignatureDays ) / 2 ) return false;
            var list = SystemList.Create( keys, current.Seq + 1, current.Entries, current.RouteHosts, utcNow );
            await AdoptOwnAsync( monitor, list ).ConfigureAwait( false );
            return true;
        }
        finally
        {
            _updateLock.Release();
        }
    }

    /// <summary>
    /// Adopts a list when it is newer than the one held and its signature is the Authentication Center's: it is stored,
    /// applied to the keys of the local party (the revoked remotes are cut) and relayed to its other remotes of the System.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="encoded">The encoded list.</param>
    /// <param name="from">The remote that sent it, null when it is created here.</param>
    /// <returns>True when the list has been adopted.</returns>
    public async Task<bool> TryAdoptAsync( IActivityMonitor monitor, byte[] encoded, IRemoteParty? from )
    {
        Throw.CheckNotNullArgument( encoded );
        if( !SystemList.TryDecode( encoded, out var list ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{from}' sent an invalid System list to '{Local}': it is ignored." );
            return false;
        }
        if( _current != null && list!.Seq <= _current.Seq ) return false;
        // Verified before the lock: getting the key events of the AuthCenter may cross the network (a list with an unknown
        // issuer can come from any remote), the adoption of a genuine list must not wait behind it.
        var verdict = await _center.CheckWithKeyEventsAsync( monitor, SystemList.Purpose, list!.SignedData.ToArray(), list.Signature ).ConfigureAwait( false );
        if( verdict != SignatureVerdict.Valid )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The {list} sent by '{from}' to '{Local}' is not signed by its AuthCenter '{_center.AuthCenterFullName}' ({verdict}): it is ignored." );
            return false;
        }
        await _adoptLock.WaitAsync().ConfigureAwait( false );
        try
        {
            if( _current != null && list.Seq <= _current.Seq ) return false;
            Local.LocalFileStore.WriteAtomically( FilePath, s => s.Write( encoded ) );
            var previousHosts = _current?.RouteHosts ?? [];
            _current = list;
            _routeHosts = GetRouteHosts( _center, list );
            monitor.Info( $"{list} of the AuthCenter '{_center.AuthCenterFullName}' is adopted by '{Local}'{(from != null ? $" (from '{from}')" : "")}." );
            await Local.GetRequiredFeature<ILocalKeys>().SetRevocationsAsync( monitor, list.Entries ).ConfigureAwait( false );
            if( _onRouteHostsChanged != null && !previousHosts.SequenceEqual( list.RouteHosts ) )
            {
                await _onRouteHostsChanged( monitor ).ConfigureAwait( false );
            }
            foreach( var r in Local.Remotes )
            {
                if( r != from
                    && IsInSystem( r )
                    && r.GetFeature<TransportFeature>()?.ConnectionAvailability == ConnectionAvailability.Connected )
                {
                    Send( monitor, r, list );
                }
            }
            return true;
        }
        finally
        {
            _adoptLock.Release();
        }
    }
}

/// <summary>
/// Handles the <see cref="ISystemListCommand"/> sent by a remote: the list is adopted when it is newer and verifies
/// (see <see cref="AuthCenterSystemList.TryAdoptAsync"/>). Ignored by a local party without Authentication Center.
/// </summary>
public sealed class SystemListHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the command.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="caller">The remote that sent it.</param>
    /// <returns>The awaitable.</returns>
    [CommandHandler]
    public async Task HandleAsync( IActivityMonitor monitor, ISystemListCommand command, IRemoteParty caller )
    {
        if( caller.Owner.GetFeature<AuthCenterSystemList>() is { } revocations && command.Encoded != null )
        {
            await revocations.TryAdoptAsync( monitor, command.Encoded, caller ).ConfigureAwait( false );
        }
    }
}
