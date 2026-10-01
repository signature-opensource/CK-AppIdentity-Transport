using CK.AppIdentity;
using CK.Core;
using System;

namespace CK.Testing.AppIdentity.TransportLayer;

/// <summary>
/// Test clock that can introduce an <see cref="Offset"/> in its time.
/// </summary>
public sealed class SystemClockTester : ApplicationIdentityService.ISystemClock
{
    readonly int _heatBeatPeriod;
    TimeSpan _offset;

    /// <summary>
    /// Gets a clock with no offset and a 0 <see cref="ApplicationIdentityService.ISystemClock.HeartBeatPeriod"/>: the
    /// <see cref="AppIdentityAgent"/> will not allocate any timer.
    /// </summary>
    public static readonly ApplicationIdentityService.ISystemClock NoHeartBeat = new SystemClockTester( 0 );

    public SystemClockTester( int heartBeatPeriod )
    {
        Throw.CheckArgument( heartBeatPeriod >= 0 );
        _heatBeatPeriod = heartBeatPeriod;
    }

    public int HeartBeatPeriod => _heatBeatPeriod;

    public DateTime UtcNow => DateTime.UtcNow + _offset;

    public TimeSpan Offset
    {
        get => _offset;
        set => _offset = value;
    }

}
