using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter.Enlistment;

/// <summary>
/// Asks the Authentication Center its current <see cref="EnlistmentUrlStatement"/> (encoded), null when it knows no
/// approval page. Sent by every party that has an Authentication Center, on the channel or along the "AuthCenter" route,
/// at start and then every <see cref="AuthCenterPeeringAuthority.PullPeriod"/>. Internal to the System.
/// </summary>
[Internal]
public interface IGetEnlistmentUrlQCommand : ICommand<byte[]?>
{
}

/// <summary>
/// The <see cref="IPeeringAuthority"/> of a System that has an Authentication Center: the authority of a local party is its
/// Authentication Center (<see cref="CrisAuthCenter"/>, pinned or anchored).
/// <list type="bullet">
///   <item>On the Authentication Center, the <see cref="EnlistmentUrlStatement"/> states the target of its "Enlistment"
///   route; it is signed on demand, again at half-life or when the target changes.</item>
///   <item>The other parties ask it (<see cref="IGetEnlistmentUrlQCommand"/>) at start then every <see cref="PullPeriod"/>
///   (every <see cref="RetryPeriod"/> while it can't be obtained), and keep the newest one that verifies.</item>
/// </list>
/// The <see cref="PinGrant"/> is signed by <see cref="AuthCenterApprovalCountersignature"/>.
/// </summary>
public sealed class AuthCenterPeeringAuthority : IPeeringAuthority
{
    /// <summary>
    /// The period of the pull of the statement from the Authentication Center: 1 hour.
    /// </summary>
    public static readonly TimeSpan PullPeriod = TimeSpan.FromHours( 1 );

    /// <summary>
    /// The period of the pull while the statement can't be obtained (the route to the Authentication Center may not be
    /// known yet): 30 seconds.
    /// </summary>
    public static readonly TimeSpan RetryPeriod = TimeSpan.FromSeconds( 30 );

    readonly ApplicationIdentityService _identity;
    readonly IServiceProvider _services;
    readonly ConcurrentDictionary<ILocalParty, AnchoredStatement> _urls;
    readonly ConcurrentDictionary<ILocalParty, DateTime> _nextPulls;
    readonly object _signLock;
    int _pulling;

    /// <summary>
    /// Initializes the authority.
    /// </summary>
    /// <param name="identity">The application identity service (its heartbeat drives the pulls).</param>
    /// <param name="services">The root services (a pull sends its query from its own scope).</param>
    public AuthCenterPeeringAuthority( ApplicationIdentityService identity, IServiceProvider services )
    {
        _identity = identity;
        _services = services;
        _urls = new ConcurrentDictionary<ILocalParty, AnchoredStatement>();
        _nextPulls = new ConcurrentDictionary<ILocalParty, DateTime>();
        _signLock = new object();
        identity.Heartbeat.Async += OnHeartbeatAsync;
    }

    /// <inheritdoc />
    public string? GetAuthority( ILocalParty local ) => local.GetFeature<CrisAuthCenter>()?.AuthCenterFullName;

    /// <inheritdoc />
    public AnchoredStatement? GetEnlistmentUrl( ILocalParty local )
    {
        var center = local.GetFeature<CrisAuthCenter>();
        if( center == null ) return null;
        if( center.AuthCenter == local ) return GetOrSign( ActivityMonitor.StaticLogger, local );
        return _urls.TryGetValue( local, out var s ) && s.Expiration > local.ApplicationIdentityService.SystemClock.UtcNow ? s : null;
    }

    // On the Authentication Center: the statement of the target of its "Enlistment" route, signed again at half-life or
    // when the target changes. Null when it knows no approval page. The routes of the center are the authorized ones (its
    // System list rules them, see AuthCenterRouteHostAuthority): the stated URL is the one of an authorized host.
    AnchoredStatement? GetOrSign( IActivityLineEmitter logger, ILocalParty center )
    {
        var target = TransportFeatureDriver.GetEnlistmentRoute( center )?.Target;
        if( target == null )
        {
            _urls.TryRemove( center, out _ );
            return null;
        }
        var utcNow = center.ApplicationIdentityService.SystemClock.UtcNow;
        lock( _signLock )
        {
            if( _urls.TryGetValue( center, out var current )
                && EnlistmentUrlStatement.TryRead( current ) == target
                && current.Expiration - utcNow > EnlistmentUrlStatement.Lifetime / 2 )
            {
                return current;
            }
            if( System.Text.Encoding.UTF8.GetByteCount( target ) > EnlistmentUrlStatement.MaxUrlLength ) return null;
            var s = EnlistmentUrlStatement.Create( center.GetRequiredFeature<ILocalKeys>(), target, utcNow );
            _urls[center] = s;
            logger.Info( $"The AuthCenter '{center}' states its approval page '{target}' until {s.Expiration:O}." );
            return s;
        }
    }

    // The heartbeat runs on the agent loop: the pulls run in the background.
    Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount, CancellationToken cancel )
    {
        if( Interlocked.CompareExchange( ref _pulling, 1, 0 ) != 0 ) return Task.CompletedTask;
        var app = _identity;
        var utcNow = app.SystemClock.UtcNow;
        var due = app.TenantDomains.Cast<ILocalParty>()
                     .Prepend( app )
                     .Where( l => l.GetFeature<CrisAuthCenter>() is { } c && c.AuthCenter != l
                                  && (!_nextPulls.TryGetValue( l, out var next ) || next <= utcNow) )
                     .ToArray();
        if( due.Length == 0 )
        {
            _pulling = 0;
            return Task.CompletedTask;
        }
        _ = Task.Run( async () =>
        {
            var m = new ActivityMonitor( "Pulling the approval page stated by the AuthCenter." );
            try
            {
                foreach( var local in due )
                {
                    var ok = await PullAsync( m, local ).ConfigureAwait( false );
                    _nextPulls[local] = app.SystemClock.UtcNow + (ok ? PullPeriod : RetryPeriod);
                }
            }
            catch( Exception ex )
            {
                m.Error( "While pulling the approval page stated by the AuthCenter.", ex );
            }
            finally
            {
                m.MonitorEnd();
                _pulling = 0;
            }
        } );
        return Task.CompletedTask;
    }

    /// <summary>
    /// Asks the Authentication Center of a local party its current statement and keeps it when it verifies and is newer
    /// than the one held.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="local">The local party.</param>
    /// <returns>True when a statement is held (the one received or a newer one).</returns>
    public async Task<bool> PullAsync( IActivityMonitor monitor, ILocalParty local )
    {
        var center = local.GetFeature<CrisAuthCenter>();
        if( center == null || center.AuthCenter == local ) return false;
        var sender = _services.GetService<PartyRoutedCommandSender>();
        if( sender == null ) return false;
        object? result;
        await using( var scope = _services.CreateAsyncScope() )
        {
            try
            {
                var command = scope.ServiceProvider.GetRequiredService<PocoDirectory>().Create<IGetEnlistmentUrlQCommand>();
                var sending = center.AuthCenter != null
                                ? sender.SendAlongPathAsync( monitor, scope.ServiceProvider, local, command, [local.FullName.Path, center.AuthCenterFullName] )
                                : sender.SendAsync( monitor, scope.ServiceProvider, local, command, AuthCenterFeature.RouteName, center.AuthCenterFullName );
                // Bounded by the sender's timeout: the scope outlives the send.
                result = await sending.ConfigureAwait( false );
            }
            catch( Exception ex )
            {
                monitor.Warn( $"Unable to ask the AuthCenter '{center.AuthCenterFullName}' its approval page.", ex );
                return false;
            }
        }
        if( result is not byte[] encoded )
        {
            if( result != null ) monitor.Warn( $"The AuthCenter '{center.AuthCenterFullName}' can't be asked its approval page: {result}." );
            return false;
        }
        if( !AnchoredStatement.TryDecode( encoded, out var statement )
            || EnlistmentUrlStatement.TryRead( statement! ) == null
            || statement!.SignerFullName != center.AuthCenterFullName )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The approval page received by '{local}' from its AuthCenter '{center.AuthCenterFullName}' is invalid: ignored." );
            return false;
        }
        if( _urls.TryGetValue( local, out var held ) && held.Expiration >= statement.Expiration ) return true;
        var verdict = statement.Verify( monitor, local.GetRequiredFeature<ILocalKeys>(), EnlistmentUrlStatement.Purpose );
        if( verdict != SignatureVerdict.Valid )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The approval page received by '{local}' is not signed by its AuthCenter '{center.AuthCenterFullName}' ({verdict}): ignored." );
            return false;
        }
        _urls[local] = statement;
        monitor.Info( $"'{local}' holds the approval page '{EnlistmentUrlStatement.TryRead( statement )}' stated by its AuthCenter '{center.AuthCenterFullName}' until {statement.Expiration:O}." );
        return true;
    }

    /// <summary>
    /// Answers the current <see cref="EnlistmentUrlStatement"/> of this Authentication Center (encoded), null when it knows
    /// no approval page (or when it is not an Authentication Center).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="current">The local party.</param>
    /// <returns>The encoded statement or null.</returns>
    [CommandHandler]
    public byte[]? Handle( IActivityMonitor monitor, IGetEnlistmentUrlQCommand command, CurrentLocalParty current )
    {
        var local = current.LocalParty;
        if( local.GetFeature<CrisAuthCenter>()?.AuthCenter != local ) return null;
        return GetOrSign( monitor, local )?.Encode();
    }
}
