namespace CK.Core;

/// <summary>
/// Simple connection availability model.
/// </summary>
public enum ConnectionAvailability
{
    /// <summary>
    /// Not connected. No data can be send to the remote.
    /// </summary>
    None,

    /// <summary>
    /// A transport is still connected but the remote no longer answers the keep-alive probes.
    /// An answer to a probe restores <see cref="Connected"/>.
    /// </summary>
    DangerZone,

    /// <summary>
    /// The negotiated transport to the remote died and a reconnection attempt is scheduled.
    /// </summary>
    Low,

    /// <summary>
    /// The remote is available.
    /// </summary>
    Connected
}
