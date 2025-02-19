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
    /// The connection to the remote has been lost for a long time. 
    /// </summary>
    DangerZone,

    /// <summary>
    /// The remote is not currently connected but was recently.
    /// </summary>
    Low,

    /// <summary>
    /// The remote is available.
    /// </summary>
    Connected
}
