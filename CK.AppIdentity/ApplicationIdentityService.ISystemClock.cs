using CK.Core;
using System;

namespace CK.AppIdentity
{
    public sealed partial class ApplicationIdentityService
    {
        /// <summary>
        /// Optional system clock that when available in the DI container provided to <see cref="TransportFeatureDriver"/>
        /// enables the time to be set and the heart beat rate used by the back tasks to be configured.
        /// <para>
        /// This should be used mainly for tests. When not registered in tne DI container, <see cref="DefaultClock"/> is used.
        /// </para>
        /// </summary>
        public interface ISystemClock : Core.ISystemClock
        {
            /// <summary>
            /// Attempts to set the ambient system (or process) time by adding <paramref name="offset"/> to the
            /// current <see cref="Core.ISystemClock.UtcNow"/> value.
            /// </summary>
            /// <param name="monitor">The monitor to use.</param>
            /// <param name="offset">The offset to apply.</param>
            /// <returns>True on success, false if adjusting time failed or is not possible.</returns>
            bool TryAdjustCurrentTime( IActivityMonitor monitor, TimeSpan offset );

            /// <summary>
            /// Gets the heart beat period in milliseconds.
            /// Defaults to 1000 ms (1 second that is the maximum).
            /// Must be between 20 and 1000.
            /// </summary>
            int HeatBeatPeriod { get; }
        }

        sealed class NoSystemClock : ISystemClock
        {
            public DateTime UtcNow => DateTime.UtcNow;

            public int HeatBeatPeriod => 1000;

            public bool TryAdjustCurrentTime( IActivityMonitor monitor, TimeSpan offset )
            {
                monitor.Error( "TryAdjustCurrentTime is not implemented yet." );
                return false;
            }
        }

        /// <summary>
        /// Gets a default clock directly bound to <see cref="DateTime.UtcNow"/>
        /// with a 1 second (1000 ms) <see cref="ISystemClock.HeatBeatPeriod"/>.
        /// </summary>
        public static readonly ISystemClock DefaultClock = new NoSystemClock();
    }
}
