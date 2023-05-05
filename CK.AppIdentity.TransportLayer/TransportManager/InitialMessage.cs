using CK.Core;
using System.Buffers;
using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Internal immutable initial message.
    /// </summary>
    sealed class InitialMessage
    {
        // The maximum number of possible versions per protocol.
        const int MaxVersionPerProtocolCount = 4;

        public const int MaxProtocolFullNameCount = MessageProtocolMap.MaxCount * MaxVersionPerProtocolCount;

        /// <summary>
        /// The <see cref="CoreApplicationIdentity.InstanceId"/> is currently 21 characters long.
        /// </summary>
        const int InstanceIdMaxLength = 21;
        const int MaxPublicKeyCount = 2;
        const int MaxPublicKeySize = 2048; // To be tested...
        // Used as a high limit so that weirdly big messages are just skipped.
        // Note that each string or array read are also protected.
        public const int MaxLength = 8 // "CK-AppId"
                                   + 5 // Version (allows uint.MaxValue)
                                   + (1 + InstanceIdMaxLength) // InstanceId
                                   + (2 + CoreApplicationIdentity.FullNameMaxLength) // Party' FullName
                                   + 5 // Number of protocol names (allows uint.MaxValue)
                                   + MaxProtocolFullNameCount * (2 + MessageProtocol.FullNameMaxLength)
                                   + 5 // Number of public keys (allows uint.MaxValue)
                                   + MaxPublicKeyCount * (4 + MaxPublicKeySize);

        readonly string _incomingFullName;
        readonly string _endPointDescription;
        readonly string _remoteEndPointDescription;
        readonly string _instanceId;
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

            public IEnumerator<string> GetEnumerator() => _p.Select( p => p.FullName ).GetEnumerator();

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

        /// <summary>
        /// Outgoing message constructor. 
        /// </summary>
        /// <param name="f">The remote party.</param>
        public InitialMessage( TransportFeature f )
        {
            Debug.Assert( f.RegisteredProtocols.Count <= MaxProtocolFullNameCount );
            _incomingFullName = f.Party.ApplicationIdentity.Local.FullName;
            _instanceId = CoreApplicationIdentity.InstanceId;
            _endPointDescription = string.Empty;
            _remoteEndPointDescription = string.Empty;
            _availableProtocols = new ProtocolAdapter( f.RegisteredProtocols );
            // TODO: f.Party.GetPublicKeys();
            _publicKeys = Array.Empty<PublicKey>();
        }

        InitialMessage( string endPointDescription,
                        string remoteEndPointDescription,
                        int version,
                        string instanceId,
                        string incomingFullName,
                        string[] protocols,
                        PublicKey[] publicKeys )
        {
            _endPointDescription = endPointDescription;
            _remoteEndPointDescription = remoteEndPointDescription;
            _version = version;
            _instanceId = instanceId;
            _incomingFullName = incomingFullName;
            _availableProtocols = protocols;
            _publicKeys = publicKeys;
        }

        /// <summary>
        /// Incoming message parse: the end point that received it must provide its
        /// description (<see cref="TransportListener.EndPointDescription"/>) and the transport description (<see cref="Transport.RemoteEndPointDescription"/>).
        /// <para>
        /// False is returned only if <paramref name="otherVersion"/> is -1 (the "CK-AppId" ASCII characters prefix is missing)
        /// or if the version is above our, otherwise this always throw on bad data.
        /// </para>
        /// </summary>
        /// <param name="endPointDescription">The endpoint description.</param>
        /// <param name="remoteEndPointDescription">The remote end point description.</param>
        /// <param name="m">The incoming transport message.</param>
        /// <param name="initialMessage">The parsed message on success.</param>
        /// <param name="otherVersion">The other version or -1 if prefix is missing.</param>
        public static bool TryParse( string endPointDescription,
                                     string remoteEndPointDescription,
                                     TransportMessageImpl m,
                                     [NotNullWhen(true)]out InitialMessage? initialMessage,
                                     out int otherVersion )
        {
            initialMessage = null;
            var r = new FastByteReader( m.Payload );
            Span<byte> header = stackalloc byte[8];
            r.ReadBytes( header );
            if( !header.SequenceEqual( _prefix ) )
            {
                otherVersion = -1;
                return false;
            }
            otherVersion = checked( (int)r.ReadSmallUInt32() );
            if( otherVersion > ZeroProtocol.CurrentVersion ) return false;

            var instanceId = r.ReadString( InstanceIdMaxLength );
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
            initialMessage = new InitialMessage( endPointDescription, remoteEndPointDescription, otherVersion, instanceId, fullName, protocols, keys );
            return true;
        }

        public void WriteCurrentVersion( ref FastByteWriter w )
        {
            w.WriteBytes( _prefix );
            w.WriteSmallUInt32( ZeroProtocol.CurrentVersion );
            w.WriteString( _instanceId );
            w.WriteString( _incomingFullName );
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

        /// <summary>
        /// Gets the "0 Protocol" version.
        /// </summary>
        public int Version => _version;

        /// <summary>
        /// Gets the <see cref="TransportListener.EndPointDescription"/> that received this message.
        /// It's the empty string for an outgoing message.
        /// </summary>
        public string IncomingEndPointDescription => _endPointDescription;

        /// <summary>
        /// Gets the <see cref="Transport.RemoteEndPointDescription"/> of the transport.
        /// It's the empty string for an outgoing message.
        /// </summary>
        public string RemoteEndPointDescription => _remoteEndPointDescription;

        /// <summary>
        /// Gets the instance identifier of the calling process.
        /// It's this <see cref="Core.CoreApplicationIdentity.InstanceId"/> for an outgoing message.
        /// </summary>
        public string InstanceId => _instanceId;

        /// <summary>
        /// Gets the incoming party name: it is the <see cref="ILocalParty.Name"/> of the 
        /// <see cref="ApplicationIdentityBase.Local"/> that sends the message.
        /// <para>
        /// It can be the root local name, or a <see cref="DomainApplicationIdentity"/> local name.
        /// </para>
        /// </summary>
        public string IncomingFullName => _incomingFullName;

        /// <summary>
        /// Gets the list of protocols with their versions that are supported.
        /// </summary>
        public IReadOnlyCollection<string> AvailableProtocols => _availableProtocols;

        /// <summary>
        /// Gets the list of public keys that identify the incoming remote.
        /// </summary>
        public IReadOnlyList<PublicKey> PublicKeys => _publicKeys;

    }
}
