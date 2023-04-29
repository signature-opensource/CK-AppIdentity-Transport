using CK.Core;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Captures the monitor identifier and time of the <see cref="IRequest"/> instance creation.
    /// </summary>
    /// <param name="OriginatorId">The originating monitor identifier.</param>
    /// <param name="TimeStamp">The creation time stamp.</param>
    public readonly record struct RequestIdentifier( string OriginatorId, DateTimeStamp TimeStamp );
}
