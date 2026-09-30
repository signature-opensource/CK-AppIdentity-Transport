using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AppIdentity.TransportLayer.Testing;

/// <summary>
/// Test clock that can introduce an <see cref="Offset"/> in its time.
/// </summary>
public sealed class SystemClockTester : ApplicationIdentityService.ISystemClock
{
    readonly int _heatBeatPeriod;
    TimeSpan _offset;

    public SystemClockTester( int heartBeatPeriod )
    {
        _heatBeatPeriod = heartBeatPeriod;
    }

    public int HeatBeatPeriod => _heatBeatPeriod;

    public DateTime UtcNow => DateTime.UtcNow + _offset;

    public TimeSpan Offset
    {
        get => _offset;
        set => _offset = value;
    }

}
