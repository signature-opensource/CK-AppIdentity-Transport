using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Describes a message encoding and/or protocol.
    /// </summary>
    public readonly struct MessageEncoding : IEquatable<MessageEncoding>
    {
        private readonly string _name;
        private readonly bool _isPartySpecific;

        /// <summary>
        /// Gets the "0 Protocol" singleton.
        /// </summary>
        public static readonly MessageEncoding ZeroProtocol = new MessageEncoding( "0 Protocol", false );

        internal MessageEncoding( string name, bool isPartySpecific = false )
        {
            _name = name;
            _isPartySpecific = isPartySpecific;
        }

        /// <summary>
        /// Gets this encoding name.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets whether this encoding is specific to the parties.
        /// </summary>
        public bool IsPartySpecific => _isPartySpecific;

        public override bool Equals( [NotNullWhen( true )] object? obj ) => obj is MessageEncoding message && Equals( message );

        public bool Equals( MessageEncoding other ) => ReferenceEquals( _name, other._name ) && _isPartySpecific == other._isPartySpecific;

        public override int GetHashCode() => _name.GetHashCode();

        public static bool operator ==( MessageEncoding left, MessageEncoding right ) => left.Equals( right );

        public static bool operator !=( MessageEncoding left, MessageEncoding right ) => !(left == right);

        public override string ToString() => _isPartySpecific ? $"{Name} (PartySpecific)" : _name;
    }
}
