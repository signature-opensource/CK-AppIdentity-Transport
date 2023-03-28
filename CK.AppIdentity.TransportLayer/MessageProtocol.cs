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

        readonly string _fullName;
        readonly string _name;
        readonly int _version;
        readonly bool _isPartySpecific;

        /// <summary>
        /// Gets the "0 Protocol" singleton.
        /// </summary>
        public static readonly MessageProtocol ZeroProtocol = new MessageProtocol( MessageProtocolDirectoryService.FormatFullName( "0 Protocol", TransportLayer.ZeroProtocol.CurrentVersion ),
                                                                                   "0 Protocol",
                                                                                   TransportLayer.ZeroProtocol.CurrentVersion,
                                                                                   false );

        internal MessageProtocol( string fullName, string name, int version, bool isPartySpecific = false )
        {
            Debug.Assert( fullName.Length <= FullNameMaxLength );
            _fullName = fullName;
            _name = name;
            _version = version;
            _isPartySpecific = isPartySpecific;
        }

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
        public int Version => _version;

        /// <summary>
        /// Gets whether this protocol is specific to the parties.
        /// </summary>
        public bool IsPartySpecific => _isPartySpecific;

        /// <summary>
        /// Overridden to return the <see cref="FullName"/>.
        /// </summary>
        /// <returns>The full name.</returns>
        public override string ToString() => _isPartySpecific ? $"{_fullName} (PartySpecific)" : _fullName;
    }
}
