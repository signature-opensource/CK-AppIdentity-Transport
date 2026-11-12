using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter.Tests;

/// <summary>
/// The key events requests triggered by signatures of an unknown issuer are throttled (AC-8): anyone can send forged
/// System lists concurrently, they must not each cost a request to the Authentication Center.
/// </summary>
[TestFixture]
public class KeyEventsRefreshGateTests
{
    [Test]
    public async Task concurrent_callers_share_one_request_and_none_starts_within_the_interval_Async()
    {
        var gate = new KeyEventsRefreshGate();
        var now = new DateTime( 2026, 11, 12, 0, 0, 0, DateTimeKind.Utc );
        int count = 0;
        var release = new TaskCompletionSource<bool>( TaskCreationOptions.RunContinuationsAsynchronously );
        async ValueTask<bool> RefreshAsync()
        {
            Interlocked.Increment( ref count );
            return await release.Task;
        }

        var calls = Enumerable.Range( 0, 10 ).Select( _ => gate.RunAsync( RefreshAsync, () => now ).AsTask() ).ToArray();
        release.SetResult( true );
        (await Task.WhenAll( calls )).ShouldAllBe( r => r );
        count.ShouldBe( 1, "The concurrent callers share the request in flight." );

        // Within the interval: no request.
        now += TimeSpan.FromMilliseconds( 500 );
        (await gate.RunAsync( RefreshAsync, () => now )).ShouldBeFalse();
        count.ShouldBe( 1 );

        // After it: a new one.
        now += KeyEventsRefreshGate.MinInterval;
        (await gate.RunAsync( RefreshAsync, () => now )).ShouldBeTrue();
        count.ShouldBe( 2 );
    }
}
