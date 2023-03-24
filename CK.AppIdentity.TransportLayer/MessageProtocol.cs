using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Describes a message protocol.
    /// </summary>
    public readonly struct MessageProtocol : IEquatable<MessageProtocol>
    {
        private readonly string _name;
        private readonly bool _isPartySpecific;

        /// <summary>
        /// Gets the "0 protocol" singleton.
        /// </summary>
        public static readonly MessageProtocol ZeroProtocol = new MessageProtocol( "0 Protocol", false );

        internal MessageProtocol( string name, bool isPartySpecific = false )
        {
            _name = name;
            _isPartySpecific = isPartySpecific;
        }

        /// <summary>
        /// Gets this protocol name.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets whether this protocol is specific to the parties.
        /// </summary>
        public bool IsPartySpecific => _isPartySpecific;

        public override bool Equals( [NotNullWhen( true )] object? obj ) => obj is MessageProtocol message && Equals( message );

        public bool Equals( MessageProtocol other ) => ReferenceEquals( _name, other._name ) && _isPartySpecific == other._isPartySpecific;

        public override int GetHashCode() => _name.GetHashCode();

        public static bool operator ==( MessageProtocol left, MessageProtocol right ) => left.Equals( right );

        public static bool operator !=( MessageProtocol left, MessageProtocol right ) => !(left == right);

        public override string ToString() => _isPartySpecific ? $"{Name} (PartySpecific)" : _name;
    }
}
