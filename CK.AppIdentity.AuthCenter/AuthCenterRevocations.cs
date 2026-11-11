using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The revocation list of a local party that has an Authentication Center (a feature of the local party, see
/// <see cref="RevocationList"/>): the newest list it verified. It is kept in its local store, applied to its keys (see
/// <see cref="ILocalKeys.SetRevocationsAsync"/>: the revoked remotes are cut) and relayed to its remotes of the System:
/// when a channel becomes available, and when a newer list is adopted (from any remote: <see cref="IRevocationListCommand"/>).
/// <para>
/// A list is adopted only when its sequence number is greater than the one held and when its signature is the
/// Authentication Center's (verified with its keys, pinned or anchored): a hop can withhold a list, not forge one.
/// </para>
/// <para>
/// The freshness: a party that is not the Authentication Center also asks it its current list every
/// <see cref="PullPeriod"/> (on the channel or along its route: <see cref="IGetRevocationListQCommand"/>), and raises a
/// <see cref="ActivityMonitor.Tags.SecurityCritical"/> alarm when the signature of the list it holds expired (the
/// Authentication Center signs it again before: an expired one means that nothing newer reached this party).
/// </para>
/// </summary>
public sealed class AuthCenterRevocations
{
    /// <summary>
    /// The name of the file of the list, in the local store of the local party.
    /// </summary>
    public const string FileName = "RevocationList.bin";

    /// <summary>
    /// The period of the pull of the current list from the Authentication Center: 1 hour.
    /// </summary>
    public static readonly TimeSpan PullPeriod = TimeSpan.FromHours( 1 );

    readonly CrisAuthCenter _center;
    readonly SemaphoreSlim _adoptLock;
    readonly Func<IActivityMonitor, Task<object?>>? _pull;
    RevocationList? _current;
    DateTime _nextPull;
    int _pulling;

    AuthCenterRevocations( CrisAuthCenter center, Func<IActivityMonitor, Task<object?>>? pull )
    {
        _center = center;
        _pull = pull;
        _adoptLock = new SemaphoreSlim( 1, 1 );
    }

    /// <summary>
    /// Gets the newest list verified here, null when none.
    /// </summary>
    public RevocationList? Current => _current;

    /// <summary>
    /// Gets the Authentication Center.
    /// </summary>
    public CrisAuthCenter Center => _center;

    ILocalParty Local => _center.Owner;

    NormalizedPath FilePath => Local.LocalFileStore.FolderPath.AppendPart( FileName );

    /// <summary>
    /// Creates the feature of a local party once its <see cref="CrisAuthCenter"/> exists (used by the two sides of the
    /// "AuthCenter" feature): the list kept in its local store is applied to its keys (it was verified when it was stored).
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="center">The Authentication Center of the local party.</param>
    /// <param name="pull">
    /// Sends an <see cref="IGetRevocationListQCommand"/> to the Authentication Center and returns its result (null for the
    /// Authentication Center itself): the periodic pull.
    /// </param>
    /// <returns>The feature.</returns>
    public static AuthCenterRevocations Plug( IActivityMonitor monitor, CrisAuthCenter center, Func<IActivityMonitor, Task<object?>>? pull )
    {
        var f = new AuthCenterRevocations( center, pull );
        var local = center.Owner;
        var bytes = StoreFileReader.TryReadAllBytes( f.FilePath );
        if( bytes != null )
        {
            if( RevocationList.TryDecode( bytes, out var list ) && local.GetFeature<ILocalKeys>() is { } keys )
            {
                f._current = list;
                keys.SetRevocationsAsync( monitor, list!.Entries ).GetAwaiter().GetResult();
                monitor.Info( $"{list} of '{local}' is loaded." );
            }
            else
            {
                monitor.Error( $"The revocation list stored by '{local}' can't be read: it will be received again from its remotes." );
            }
        }
        local.AddFeature( f );
        if( pull != null ) local.ApplicationIdentityService.Heartbeat.Async += f.OnHeartbeatAsync;
        // The transport exists once the initialization is done: the list is then sent when a channel becomes available.
        _ = local.ApplicationIdentityService.InitializationTask.ContinueWith( _ =>
        {
            if( local.ApplicationIdentityService.GetFeature<TransportManagerFeature>() is { } transport )
            {
                transport.ConnectionAvailabilityChanged.Async += f.OnConnectionAvailabilityChangedAsync;
            }
        }, TaskScheduler.Default );
        return f;
    }

    // The heartbeat runs on the agent loop: the pull and the staleness check run in the background, every PullPeriod.
    Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount, CancellationToken cancel )
    {
        var utcNow = DateTime.UtcNow;
        if( utcNow >= _nextPull && Interlocked.CompareExchange( ref _pulling, 1, 0 ) == 0 )
        {
            _nextPull = utcNow + PullPeriod;
            _ = Task.Run( async () =>
            {
                var m = new ActivityMonitor( $"Pulling the revocation list of the AuthCenter of '{Local}'." );
                try
                {
                    await PullAsync( m ).ConfigureAwait( false );
                    CheckStaleness( m, DateTime.UtcNow );
                }
                catch( Exception ex )
                {
                    m.Error( "While pulling the revocation list.", ex );
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
            monitor.Warn( $"Unable to ask the AuthCenter '{_center.AuthCenterFullName}' its revocation list.", ex );
            return false;
        }
        if( result is byte[] encoded ) return await TryAdoptAsync( monitor, encoded, null ).ConfigureAwait( false );
        if( result != null ) monitor.Warn( $"The AuthCenter '{_center.AuthCenterFullName}' can't be asked its revocation list: {result}." );
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

    void Send( IActivityMonitor monitor, IRemoteParty remote, RevocationList list )
    {
        var channel = remote.GetFeature<CrisChannelFeature>();
        if( channel == null ) return;
        var command = channel.PocoDirectory.Create<IRevocationListCommand>( c => c.Encoded = list.Encode() );
        channel.SendCommand( monitor, command );
        monitor.Trace( $"{list} sent to '{remote}'." );
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
        var current = _current;
        var keys = Local.GetRequiredFeature<ILocalKeys>();
        if( current == null || current.Signature.Expiration - utcNow > TimeSpan.FromDays( keys.MaxSignatureDays ) / 2 ) return false;
        var list = RevocationList.Create( keys, current.Seq + 1, current.Entries, utcNow );
        return await TryAdoptAsync( monitor, list.Encode(), null ).ConfigureAwait( false );
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
        if( !RevocationList.TryDecode( encoded, out var list ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{from}' sent an invalid revocation list to '{Local}': it is ignored." );
            return false;
        }
        await _adoptLock.WaitAsync().ConfigureAwait( false );
        try
        {
            if( _current != null && list!.Seq <= _current.Seq ) return false;
            var verdict = await _center.CheckWithKeyEventsAsync( monitor, RevocationList.Purpose, list!.SignedData.ToArray(), list.Signature ).ConfigureAwait( false );
            if( verdict != SignatureVerdict.Valid )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The {list} sent by '{from}' to '{Local}' is not signed by its AuthCenter '{_center.AuthCenterFullName}' ({verdict}): it is ignored." );
                return false;
            }
            Local.LocalFileStore.WriteAtomically( FilePath, s => s.Write( encoded ) );
            _current = list;
            monitor.Info( $"{list} of the AuthCenter '{_center.AuthCenterFullName}' is adopted by '{Local}'{(from != null ? $" (from '{from}')" : "")}." );
            await Local.GetRequiredFeature<ILocalKeys>().SetRevocationsAsync( monitor, list.Entries ).ConfigureAwait( false );
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
/// Handles the <see cref="IRevocationListCommand"/> sent by a remote: the list is adopted when it is newer and verifies
/// (see <see cref="AuthCenterRevocations.TryAdoptAsync"/>). Ignored by a local party without Authentication Center.
/// </summary>
public sealed class RevocationListHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the command.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="caller">The remote that sent it.</param>
    /// <returns>The awaitable.</returns>
    [CommandHandler]
    public async Task HandleAsync( IActivityMonitor monitor, IRevocationListCommand command, IRemoteParty caller )
    {
        if( caller.Owner.GetFeature<AuthCenterRevocations>() is { } revocations && command.Encoded != null )
        {
            await revocations.TryAdoptAsync( monitor, command.Encoded, caller ).ConfigureAwait( false );
        }
    }
}
