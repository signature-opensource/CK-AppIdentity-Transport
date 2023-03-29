using CK.Core;
using System.Buffers;
using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Internal immutable initial message that implements the public <see cref="IUnknownRemote"/>:
    /// by keeping this message we can discover new remotes that want to enter the system.
    /// </summary>
    sealed class InitialMessage : IUnknownRemote
    {
        // The maximum number of possible versions per protocol.
        const int MaxVersionPerProtocolCount = 3;

        public const int MaxProtocolFullNameCount = MessageProtocolMap.MaxCount * MaxVersionPerProtocolCount;

        const int MaxPublicKeyCount = 2;
        const int MaxPublicKeySize = 2048; // To be tested...
        // Used as a high limit so that weirdly big messages are just skipped.
        // Note that each string or array read are also protected.
        public const int MaxLength = 8 // "CK-AppId"
                                   + 5 // Version (allows uint.MaxValue)
                                   + (2 + CoreApplicationIdentity.FullNameMaxLength) // Party' FullName
                                   + 5 // Number of protocol names (allows uint.MaxValue)
                                   + MaxProtocolFullNameCount * (2 + MessageProtocol.FullNameMaxLength)
                                   + 5 // Number of public keys (allows uint.MaxValue)
                                   + MaxPublicKeyCount * (4 + MaxPublicKeySize);

        readonly string _fullName;
        readonly string _endPointDescription;
        readonly int _version;

        // Prefix is "CK-AppId" in ASCII.
        static ReadOnlySpan<byte> _prefix => new byte[]{ 0x43, 0x4b, 0x2d, 0x41, 0x70, 0x70, 0x49, 0x64 }; 

        // For an outgoing message, TransportFeature.AvailableProtocols is
        // adapted: no concurrency issues here, see TransportFeature.AvailableProtocols
        // code comments.
        // For an ingoing message, this is an array.
        readonly IReadOnlyCollection<string> _availableProtocols;
        readonly PublicKey[] _publicKeys;

        sealed class ProtocolAdapter : IReadOnlyCollection<string>
        {
            readonly IReadOnlySet<MessageProtocol> _p;

            public ProtocolAdapter( IReadOnlySet<MessageProtocol> p ) => _p = p;

            public int Count => _p.Count;

            public IEnumerator<string> GetEnumerator() => _p.Select( p => p.Name ).GetEnumerator();

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

        /// <summary>
        /// Outgoing message constructor. 
        /// </summary>
        /// <param name="p">The remote party.</param>
        public InitialMessage( TransportLayerFeature f )
        {
            Debug.Assert( f.RegisteredProtocols.Count <= MaxProtocolFullNameCount );
            _fullName = f.Party.FullName;
            _endPointDescription = string.Empty;
            _availableProtocols = new ProtocolAdapter( f.RegisteredProtocols );
            // TODO: f.Party.GetPublicKeys();
            _publicKeys = Array.Empty<PublicKey>();
        }

        InitialMessage( string endPointDescription, int version, string fullName, string[] protocols, PublicKey[] publicKeys )
        {
            _endPointDescription = endPointDescription;
            _version = version;
            _fullName = fullName;
            _availableProtocols = protocols;
            _publicKeys = publicKeys;
        }

        /// <summary>
        /// Incoming message parse: the end point that received it must provide its
        /// description (<see cref="TransportListener.EndPointDescription"/>).
        /// <para>
        /// False is returned only if <paramref name="otherVersion"/> is -1 (the "CK-AppId" ASCII characters prefix is missing)
        /// or if the version is above our, otherwise this always throw on bad data.
        /// </para>
        /// </summary>
        /// <param name="endPointDescription">The endpoint description.</param>
        /// <param name="m">The incoming transport message.</param>
        /// <param name="initialMessage">The parsed message on success.</param>
        /// <param name="otherVersion">The other version or -1 if prefix is missing.</param>
        public static bool TryParse( string endPointDescription, TransportMessage m, [NotNullWhen(true)]out InitialMessage? initialMessage, out int otherVersion )
        {
            initialMessage = null;
            var r = new FastByteReader( m.Message );
            Span<byte> header = stackalloc byte[8];
            r.ReadBytes( header );
            if( !header.SequenceEqual( _prefix ) )
            {
                otherVersion = -1;
                return false;
            }
            otherVersion = checked( (int)r.ReadSmallUInt32() );
            if( otherVersion > ZeroProtocol.CurrentVersion ) return false;

            var fullName = r.ReadString( CoreApplicationIdentity.FullNameMaxLength );
            var protocolCount = r.ReadSmallUInt32();
            Throw.CheckData( protocolCount <= MaxProtocolFullNameCount );
            string[] protocols = new string[protocolCount];
            for( int i = 0; i < protocols.Length; i++ )
            {
                protocols[i] = r.ReadString( MessageProtocol.FullNameMaxLength );
            }
            var keyCount = r.ReadSmallUInt32();
            Throw.CheckData( keyCount <= MaxPublicKeyCount );
            PublicKey[] keys = new PublicKey[keyCount];
            for( int i = 0; i < keys.Length; i++ )
            {
                var lenPublicKey = r.ReadSmallUInt32();
                Throw.CheckData( lenPublicKey <= MaxPublicKeySize );
                var bytes = r.ReadBytes( lenPublicKey );
                keys[i] = PublicKey.CreateFromSubjectPublicKeyInfo( bytes, out int bytesRead );
                Throw.CheckData( bytesRead == bytes.Length );
            }
            initialMessage = new InitialMessage( endPointDescription, otherVersion, fullName, protocols, keys );
            return true;
        }

        public void WriteCurrentVersion( ref FastByteWriter w )
        {
            w.WriteBytes( _prefix );
            w.WriteSmallUInt32( ZeroProtocol.CurrentVersion );
            w.WriteString( _fullName );
            w.WriteSmallUInt32( (uint)_availableProtocols.Count );
            foreach( var protocol in _availableProtocols )
            {
                w.WriteString( protocol );
            }
            w.WriteSmallUInt32( (uint)_publicKeys.Length );
            foreach( var k in _publicKeys )
            {
                var bytes = k.ExportSubjectPublicKeyInfo();
                w.WriteSmallUInt32( (uint)bytes.Length );
                w.WriteBytes( bytes );
            }
        }

        public int Version => _version;

        public string IncomingEndPointDescription => _endPointDescription;

        public string FullName => _fullName;

        public IReadOnlyCollection<string> AvailableProtocols => _availableProtocols;

        public IReadOnlyList<PublicKey> PublicKeys => _publicKeys;
    }
}
