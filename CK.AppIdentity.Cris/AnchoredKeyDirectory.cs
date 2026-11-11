using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Cris;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// The key directory of the local parties: the keys of an anchored party (see <see cref="ILocalKeys.FindAnchoredKeys"/>)
/// obtained without a channel to it, by a <see cref="IGetKeyEventsQCommand"/> sent along a route that it hosts. What comes
/// back is verified from its anchor: a hop can withhold it, not forge it.
/// <para>
/// The events are fetched on demand: when nothing is held yet and when a signature has an unknown issuer (the party
/// rotated since). Concurrent fetches of the same party share one request, and a party is fetched at most once every
/// <see cref="MinFetchInterval"/>: signatures with an unknown issuer can't make a party flood the route.
/// </para>
/// </summary>
public sealed class AnchoredKeyDirectory : ISingletonAutoService
{
    /// <summary>
    /// The maximal time a fetch waits for the events: 2 seconds.
    /// </summary>
    public static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds( 2 );

    /// <summary>
    /// The minimal time between two fetches of the events of the same party: 5 seconds.
    /// </summary>
    public static readonly TimeSpan MinFetchInterval = TimeSpan.FromSeconds( 5 );

    readonly PartyRoutedCommandSender _sender;
    readonly PocoDirectory _pocoDirectory;
    readonly ConcurrentDictionary<(string Local, string Anchored), FetchState> _fetches;

    sealed class FetchState
    {
        public Task<bool>? InFlight;
        public DateTime LastFetch;
    }

    /// <summary>
    /// Initializes a new directory.
    /// </summary>
    /// <param name="sender">The routed command sender.</param>
    /// <param name="pocoDirectory">The poco directory.</param>
    public AnchoredKeyDirectory( PartyRoutedCommandSender sender, PocoDirectory pocoDirectory )
    {
        _sender = sender;
        _pocoDirectory = pocoDirectory;
        _fetches = new ConcurrentDictionary<(string, string), FetchState>();
    }

    /// <summary>
    /// Checks a signature of an anchored party: when its issuer is unknown (nothing is held yet, or the party rotated
    /// since), its events are fetched along the route (at most <see cref="FetchTimeout"/>) and the signature is checked
    /// again, once.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the calling scope (to send the routed command).</param>
    /// <param name="local">The local party.</param>
    /// <param name="fullName">The full name of the anchored party.</param>
    /// <param name="routeName">The name of a route hosted by the anchored party.</param>
    /// <param name="purpose">The purpose of the signature.</param>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>The verdict.</returns>
    public async ValueTask<SignatureVerdict> CheckAsync( IActivityMonitor monitor,
                                                         IServiceProvider services,
                                                         ILocalParty local,
                                                         string fullName,
                                                         string routeName,
                                                         string purpose,
                                                         ReadOnlyMemory<byte> data,
                                                         ApplicationSignature signature )
    {
        var keys = FindKeys( monitor, local, fullName );
        if( keys == null ) return SignatureVerdict.Refused;
        var verdict = keys.Check( monitor, purpose, data.Span, signature );
        if( verdict == SignatureVerdict.UnknownIssuer && await FetchAsync( monitor, services, local, keys, routeName ).ConfigureAwait( false ) )
        {
            verdict = keys.Check( monitor, purpose, data.Span, signature );
        }
        return verdict;
    }

    /// <summary>
    /// Fetches the events of an anchored party along a route that it hosts and applies them (see
    /// <see cref="IAnchoredKeys.ApplyEvents"/>), unless it has been fetched less than <see cref="MinFetchInterval"/> ago.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the calling scope (to send the routed command).</param>
    /// <param name="local">The local party.</param>
    /// <param name="fullName">The full name of the anchored party.</param>
    /// <param name="routeName">The name of a route hosted by the anchored party.</param>
    /// <returns>True when events were fetched and verified.</returns>
    public ValueTask<bool> RefreshAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty local, string fullName, string routeName )
    {
        var keys = FindKeys( monitor, local, fullName );
        return keys == null ? ValueTask.FromResult( false ) : FetchAsync( monitor, services, local, keys, routeName );
    }

    static IAnchoredKeys? FindKeys( IActivityMonitor monitor, ILocalParty local, string fullName )
    {
        Throw.CheckNotNullArgument( local );
        Throw.CheckNotNullOrEmptyArgument( fullName );
        var keys = local.GetRequiredFeature<ILocalKeys>().FindAnchoredKeys( fullName );
        if( keys == null ) monitor.Warn( $"'{fullName}' has no trust anchor in '{local.FullName}': its keys can't be obtained from the key directory." );
        return keys;
    }

    async ValueTask<bool> FetchAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty local, IAnchoredKeys keys, string routeName )
    {
        Throw.CheckNotNullArgument( services );
        Throw.CheckNotNullOrWhiteSpaceArgument( routeName );
        var state = _fetches.GetOrAdd( (local.FullName.Path, keys.FullName), _ => new FetchState() );
        Task<bool> fetch;
        lock( state )
        {
            if( state.InFlight == null )
            {
                var now = local.ApplicationIdentityService.SystemClock.UtcNow;
                if( now - state.LastFetch < MinFetchInterval )
                {
                    monitor.Trace( $"The key events of '{keys.FullName}' have been fetched less than {MinFetchInterval} ago." );
                    return false;
                }
                state.LastFetch = now;
                state.InFlight = DoFetchAsync( monitor, services, local, keys, routeName );
            }
            fetch = state.InFlight;
        }
        try
        {
            return await fetch.ConfigureAwait( false );
        }
        finally
        {
            lock( state )
            {
                if( state.InFlight == fetch ) state.InFlight = null;
            }
        }
    }

    async Task<bool> DoFetchAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty local, IAnchoredKeys keys, string routeName )
    {
        if( !local.Description.Routes.TryGetValue( routeName, out var route ) )
        {
            monitor.Warn( $"'{local.FullName}' has no route '{routeName}': the key events of '{keys.FullName}' can't be fetched." );
            return false;
        }
        if( route.Host != keys.FullName )
        {
            monitor.Warn( $"The route '{routeName}' of '{local.FullName}' leads to '{route.Host}', not to '{keys.FullName}': its key events can't be fetched along it." );
            return false;
        }
        var stated = keys.GetStatedCheckpoint( monitor );
        if( stated == null )
        {
            monitor.Warn( $"The trust anchor of '{keys.FullName}' can't be read yet: its key events are not fetched." );
            return false;
        }
        var query = _pocoDirectory.Create<IGetKeyEventsQCommand>( c => c.FromSeq = stated.Seq );
        object? result;
        try
        {
            result = await _sender.SendAsync( monitor, services, local, query, routeName ).WaitAsync( FetchTimeout ).ConfigureAwait( false );
        }
        catch( TimeoutException )
        {
            monitor.Warn( $"The key events of '{keys.FullName}' didn't come back along the route '{routeName}' within {FetchTimeout}." );
            return false;
        }
        if( result is not IPartyKeyEvents answer )
        {
            var error = result is ICrisResultError e ? e.Errors.Select( m => m.Text ).Concatenate() : result?.GetType().Name ?? "null";
            monitor.Warn( $"The key events of '{keys.FullName}' can't be fetched along the route '{routeName}': {error}" );
            return false;
        }
        var events = new List<KeyEvent>();
        try
        {
            var data = answer.Events.AsSpan();
            while( data.Length > 0 )
            {
                Throw.CheckData( events.Count < KeyEventChain.MaxEventWindow );
                events.Add( KeyEvent.Read( data, out int read ) );
                data = data.Slice( read );
            }
            Throw.CheckData( events.Count > 0 );
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Invalid key events of '{keys.FullName}' received along the route '{routeName}'.", ex );
            return false;
        }
        var check = keys.ApplyEvents( monitor, events );
        return check.Verdict is KeyChainVerdict.UpToDate or KeyChainVerdict.Advanced or KeyChainVerdict.Recovered or KeyChainVerdict.Abandoned;
    }
}

/// <summary>
/// Answers the <see cref="IGetKeyEventsQCommand"/>: the events of the local party.
/// </summary>
public sealed class KeyEventsHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the query.
    /// </summary>
    /// <param name="command">The query.</param>
    /// <param name="party">The local party.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The events of the local party.</returns>
    [CommandHandler]
    public IPartyKeyEvents Handle( IGetKeyEventsQCommand command, CurrentLocalParty party, PocoDirectory pocos )
    {
        var local = party.LocalParty;
        var events = local.GetRequiredFeature<ILocalKeys>().State.GetEventsFrom( command.FromSeq );
        return pocos.Create<IPartyKeyEvents>( r =>
        {
            r.PartyFullName = local.FullName.Path;
            var w = new System.Buffers.ArrayBufferWriter<byte>();
            foreach( var e in events ) System.Buffers.BuffersExtensions.Write( w, e.Encoded.Span );
            r.Events = w.WrittenSpan.ToArray();
        } );
    }
}
