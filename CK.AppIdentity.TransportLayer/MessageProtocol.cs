using CK.Core;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Describes a message protocol managed by <see cref="MessageProtocolDirectoryService"/>.
/// Reference equality can be used.
/// </summary>
public sealed class MessageProtocol
{
    /// <summary>
    /// Maximal length of <see cref="FullName"/>.
    /// </summary>
    public const int FullNameMaxLength = 255;

    readonly OutgoingMessageFactory _messageFactory;
    readonly string _fullName;
    readonly string _name;
    readonly ushort _version;
    readonly bool _isZeroProtocol;

    /// <summary>
    /// The "0 Protocol" name.
    /// </summary>
    public static readonly string ZeroProtocolName = "0 Protocol";

    /// <summary>
    /// Gets the "0 Protocol" singleton.
    /// </summary>
    public static readonly MessageProtocol ZeroProtocol = new MessageProtocol( MessageProtocolDirectoryService.FormatFullName( ZeroProtocolName, TransportLayer.ZeroProtocol.CurrentVersion ),
                                                                               ZeroProtocolName,
                                                                               TransportLayer.ZeroProtocol.CurrentVersion,
                                                                               true );

    /// <summary>
    /// Default cap on an incoming message for a channel protocol.
    /// <para>
    /// A declared length is attacker-chosen, so it must be bounded before anything is allocated for
    /// it. The run-phase read used to accept <see cref="int.MaxValue"/>, meaning a peer could ask
    /// for a 2 GiB buffer with a 5-byte header — and once frames are authenticated, that allocation
    /// happens *before* the MAC can reject it.
    /// </para>
    /// <para>
    /// A channel that legitimately carries more can raise it at registration.
    /// </para>
    /// </summary>
    public const int DefaultMaxIncomingMessageLength = 16 * 1024 * 1024;

    /// <summary>
    /// Cap for the "0 Protocol". Its run-phase traffic is tiny (keep-alive and goodbye) but the
    /// same instance carries the handshake, whose messages are the largest thing it ever sees, so
    /// this is generous while still being four orders of magnitude below 2 GiB.
    /// </summary>
    public const int ZeroProtocolMaxIncomingMessageLength = 1024 * 1024;

    readonly int _maxIncomingMessageLength;

    /// <summary>
    /// Gets the maximum length accepted for an incoming message of this protocol. A longer declared
    /// length is rejected before the payload is read.
    /// </summary>
    public int MaxIncomingMessageLength => _maxIncomingMessageLength;

    internal MessageProtocol( string fullName, string name, ushort version, bool isZeroProtocol, int maxIncomingMessageLength = 0 )
    {
        Throw.DebugAssert( fullName.Length <= FullNameMaxLength );
        _fullName = fullName;
        _name = name;
        _version = version;
        _isZeroProtocol = isZeroProtocol;
        _maxIncomingMessageLength = maxIncomingMessageLength > 0
                                        ? maxIncomingMessageLength
                                        : (isZeroProtocol ? ZeroProtocolMaxIncomingMessageLength : DefaultMaxIncomingMessageLength);
        // If the concurrent MessageProtocolDirectoryService.TryRegister loses an instance, we don't care
        // to dispose this since the lost instance will never be used and no message can be pooled.
        _messageFactory = new OutgoingMessageFactory( this );
    }

    /// <summary>
    /// Gets the message factory for this protocol.
    /// This is referenced internally and exposed by the ChannelFeature: the fact that it is
    /// centralized here is an implementation detail.
    /// </summary>
    internal OutgoingMessageFactory MessageFactory => _messageFactory;

    /// <summary>
    /// Gets this protocol name without version.
    /// </summary>
    public string Name => _name;

    /// <summary>
    /// Gets this protocol name with its version.
    /// </summary>
    public string FullName => _fullName;

    /// <summary>
    /// Gets this protocol version.
    /// </summary>
    public ushort Version => _version;

    /// <summary>
    /// Gets whether this is the "0 Protocol".
    /// </summary>
    public bool IsZeroProtocol => _isZeroProtocol;

    /// <summary>
    /// Overridden to return the <see cref="FullName"/>.
    /// </summary>
    /// <returns>The full name.</returns>
    public override string ToString() => _fullName;
}
