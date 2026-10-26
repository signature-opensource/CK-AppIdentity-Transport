using CK.Core;

namespace CK.IO.AuthCenter;

/// <summary>
/// The result of a <see cref="IRelayAuthCenterCommand"/>: the result of the relayed command.
/// </summary>
public interface IRelayAuthCenterResult : IPoco
{
    /// <summary>
    /// Gets or sets the result of the relayed command (an error result when it has been refused).
    /// </summary>
    object? Result { get; set; }
}
