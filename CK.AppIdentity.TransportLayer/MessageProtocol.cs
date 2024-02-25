using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
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

        internal MessageProtocol( string fullName, string name, ushort version, bool isZeroProtocol )
        {
            Throw.DebugAssert( fullName.Length <= FullNameMaxLength );
            _fullName = fullName;
            _name = name;
            _version = version;
            _isZeroProtocol = isZeroProtocol;
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
}
