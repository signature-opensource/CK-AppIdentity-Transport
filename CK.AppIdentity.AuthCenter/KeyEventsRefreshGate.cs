using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Throttles the key events requests of an Authentication Center triggered by signatures of an unknown issuer: anyone can
/// send such a signature (a forged System list, a token), each one must not cost a request. Concurrent callers share the
/// request in flight, and a request is not started again within <see cref="MinInterval"/> of the end of the previous one
/// (the keys just obtained are the current ones: an issuer still unknown is not the Authentication Center's).
/// </summary>
sealed class KeyEventsRefreshGate
{
    /// <summary>
    /// The minimal time between the end of a request and the start of the next one.
    /// </summary>
    public static readonly TimeSpan MinInterval = TimeSpan.FromSeconds( 1 );

    readonly object _lock = new object();
    Task<bool>? _inFlight;
    DateTime _lastEnd;

    /// <summary>
    /// Runs <paramref name="refresh"/>, or joins the one in flight, or returns false within <see cref="MinInterval"/>
    /// of the end of the previous one.
    /// </summary>
    /// <param name="refresh">Requests the key events: true when they changed what is held.</param>
    /// <param name="clock">The current time.</param>
    /// <returns>True when the key events changed what is held.</returns>
    public async ValueTask<bool> RunAsync( Func<ValueTask<bool>> refresh, Func<DateTime> clock )
    {
        TaskCompletionSource<bool>? own = null;
        Task<bool> joined;
        lock( _lock )
        {
            if( _inFlight != null )
            {
                joined = _inFlight;
            }
            else
            {
                if( _lastEnd != default && clock() - _lastEnd < MinInterval ) return false;
                own = new TaskCompletionSource<bool>( TaskCreationOptions.RunContinuationsAsynchronously );
                _inFlight = joined = own.Task;
            }
        }
        if( own == null ) return await joined.ConfigureAwait( false );
        bool result = false;
        try
        {
            result = await refresh().ConfigureAwait( false );
            return result;
        }
        finally
        {
            lock( _lock )
            {
                _inFlight = null;
                _lastEnd = clock();
            }
            own.SetResult( result );
        }
    }
}
