using CK.Core;
using System;

namespace CK.AppIdentity.BlobChannel.Tests
{
    /// <summary>
    /// Test clock that can introduce an <see cref="Offset"/> in its time.
    /// </summary>
    public sealed class SystemClockTester : ApplicationIdentityService.ISystemClock
    {
        readonly int _heatBeatPeriod;
        TimeSpan _offset;

        public SystemClockTester( int heatBeatPeriod )
        {
            _heatBeatPeriod = heatBeatPeriod;
        }

        public int HeatBeatPeriod => _heatBeatPeriod;

        public DateTime UtcNow => DateTime.UtcNow + _offset;

        public TimeSpan Offset
        {
            get => _offset;
            set => _offset = value;
        }

        bool ApplicationIdentityService.ISystemClock.TryAdjustCurrentTime( IActivityMonitor monitor, TimeSpan offset )
        {
            _offset = offset;
            return true;
        }
    }
}
