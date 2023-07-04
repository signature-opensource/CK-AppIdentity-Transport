using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Buffers;
using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
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
        const int MaxPublicKeyCount = ILocalKeys.MaxIdentityCount;
        // Signatures can have varying length but no more than 256 bytes.
        const int MaxSignatureSize = 256;
        const int MaxPublicKeySize = 8 + 2048; // TimeName (DateTime) + ...To be tested...
        // Used as a high limit so that weirdly big messages are just skipped.
        // Note that each string or array read are also protected.
        public const int MaxLength = 8 // "CK-AppId"
                                   + 5 // Version (allows uint.MaxValue)
                                   + (1 + InstanceIdMaxLength) // InstanceId
                                   + (2 + CoreApplicationIdentity.FullNameMaxLength) // Party' FullName
                                   + 5 // Number of protocol names (allows uint.MaxValue)
                                   + MaxProtocolFullNameCount * (2 + MessageProtocol.FullNameMaxLength)
                                   + 5 // Number of public keys (allows uint.MaxValue)
                                   + MaxPublicKeyCount * (4 + MaxPublicKeySize)
                                   + MaxPublicKeyCount * MaxSignatureSize;

        readonly string _endPointDescription;
        readonly string _remoteEndPointDescription;
        readonly string _domainName;
        readonly string _partyName;
        readonly string _environmentName;
        readonly string _fullName;
        readonly string _instanceId;
        readonly int _version;

        // Prefix is "CK-AppId" in ASCII.
        static ReadOnlySpan<byte> _prefix => new byte[]{ 0x43, 0x4b, 0x2d, 0x41, 0x70, 0x70, 0x49, 0x64 };

        // For an outgoing message:
        // TransportFeature.AvailableProtocols is adapted: no concurrency issues here, see TransportFeature.AvailableProtocols
        // code comments.
        // For an ingoing message, this is an array.
        readonly IReadOnlyCollection<string> _availableProtocols;
        readonly IReadOnlyList<LocalIdentityKey> _localIdentities;

        // Incoming message specific data:
        readonly IReadOnlyList<RemoteIdentityKeyData> _remoteIdentities;
        readonly byte[]? _hashMessage;
        readonly byte[][]? _signatures;

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
        /// <param name="f">The remote party's transport.</param>
        public InitialMessage( TransportFeature f )
        {
            Debug.Assert( !f.IsListening );
            Debug.Assert( f.RegisteredProtocols.Count <= MaxProtocolFullNameCount );
            var local = f.Party.Owner;
            _domainName = local.DomainName;
            _partyName = local.PartyName;
            _environmentName = local.EnvironmentName;
            _fullName = local.FullName;
            // This acts as the nonce: one instance can initiate a connexion only once.
            _instanceId = CoreApplicationIdentity.InstanceId;
            _endPointDescription = string.Empty;
            _remoteEndPointDescription = string.Empty;
            _availableProtocols = new ProtocolAdapter( f.RegisteredProtocols );
            _localIdentities = f.LocalKeys.Identities;
            _remoteIdentities = Array.Empty<RemoteIdentityKeyData>();
        }

        /// <summary>
        /// Ingoing message constructor: the <see cref="RemoteIdentityKeyData"/> keys,
        /// the SHA1 hash of the data and the signatures for each key.
        /// </summary>
        /// <param name="endPointDescription"></param>
        /// <param name="remoteEndPointDescription"></param>
        /// <param name="version"></param>
        /// <param name="instanceId"></param>
        /// <param name="incomingFullName"></param>
        /// <param name="protocols"></param>
        /// <param name="identities"></param>
        /// <param name="hashMessage"></param>
        /// <param name="signatures"></param>
        InitialMessage( string endPointDescription,
                        string remoteEndPointDescription,
                        int version,
                        string instanceId,
                        string incomingDomainName,
                        string incomingPartyName,
                        string incomingEnvironmentName,
                        string incomingFullName,
                        string[] protocols,
                        RemoteIdentityKeyData[] identities,
                        byte[] hashMessage,
                        byte[][] signatures )
        {
            _endPointDescription = endPointDescription;
            _remoteEndPointDescription = remoteEndPointDescription;
            _version = version;
            _instanceId = instanceId;
            _domainName = incomingDomainName;
            _partyName = incomingPartyName;
            _environmentName= incomingEnvironmentName;
            _fullName = incomingFullName;
            _availableProtocols = protocols;
            _remoteIdentities = identities;
            _hashMessage = hashMessage;
            _signatures = signatures;
            _localIdentities = Array.Empty<LocalIdentityKey>();
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
                                     IncomingMessage m,
                                     [NotNullWhen(true)]out InitialMessage? initialMessage,
                                     out int otherVersion )
        {
            var ros = m.Message;
            initialMessage = null;
            var r = new FastByteReader( ros );
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
            Throw.CheckData( instanceId.Length > 3 );

            var fullName = r.ReadString( CoreApplicationIdentity.FullNameMaxLength );
            Throw.CheckData( CoreApplicationIdentity.TryParseFullName( fullName, out var domainName, out var partyName, out var environmentName )
                             && domainName != null && partyName != null && environmentName != null );

            var protocolCount = r.ReadSmallUInt32();
            Throw.CheckData( protocolCount <= MaxProtocolFullNameCount );
            string[] protocols = new string[protocolCount];
            for( int i = 0; i < protocols.Length; i++ )
            {
                protocols[i] = r.ReadString( MessageProtocol.FullNameMaxLength );
            }
            var keyCount = r.ReadSmallUInt32();
            Throw.CheckData( keyCount <= MaxPublicKeyCount );
            var keys = new RemoteIdentityKeyData[keyCount];
            for( int i = 0; i < keys.Length; i++ )
            {
                var timeName = r.ReadDateTime();
                var lenPublicKey = r.ReadSmallUInt32();
                Throw.CheckData( lenPublicKey <= MaxPublicKeySize );
                var bytes = r.ReadBytes( lenPublicKey );
                var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo( bytes, out int bytesRead );
                Throw.CheckData( bytesRead == bytes.Length );
                keys[i] = new RemoteIdentityKeyData( timeName, publicKey );
            }
            // The message data itself has been read. Now comes the keyCount signatures.
            // It's time to compute the hash of the message.
            var messageHash = new byte[64];
            ZeroProtocol.ComputeHash( r.GetBeforeHead(), messageHash );
            var signatures = new byte[keyCount][];
            Debug.Assert( signatures.Length == keyCount );
            for( int i = 0; i < keys.Length; i++ )
            {
                // We could have settled the signature size (we use DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
                // but it doesn't cost much (1 byte) to let it variable so that are free to use different key size (the
                // current default is 256 bits (ECDsa creates signatures of 2 x KeySize: this is 2 * 256 / 8 = 64 bytes for
                // current key size) and this should be enough... but who knows, so let the max signature size be 256 bytes).
                var lenSignature = r.ReadByte();
                signatures[i] = r.ReadBytes( lenSignature );
            }
            initialMessage = new InitialMessage( endPointDescription,
                                                 remoteEndPointDescription,
                                                 otherVersion,
                                                 instanceId,
                                                 domainName,
                                                 partyName,
                                                 environmentName,
                                                 fullName,
                                                 protocols,
                                                 keys,
                                                 messageHash,
                                                 signatures );
            return true;
        }

        public void WriteCurrentVersion( ref FastByteWriter w )
        {
            w.WriteBytes( _prefix );
            w.WriteSmallUInt32( ZeroProtocol.CurrentVersion );
            w.WriteString( _instanceId );
            w.WriteString( _fullName );
            w.WriteSmallUInt32( (uint)_availableProtocols.Count );
            foreach( var protocol in _availableProtocols )
            {
                w.WriteString( protocol );
            }
            w.WriteSmallUInt32( (uint)_localIdentities.Count );
            foreach( var k in _localIdentities )
            {
                w.WriteDateTime( k.TimeName );
                w.WriteSmallUInt32( (uint)k.PublicKeyRawData.Length );
                w.WriteBytes( k.PublicKeyRawData.Span );
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
        /// Gets the domain name: it is the <see cref="ILocalParty"/>'s <see cref="IParty.DomainName"/>
        /// of the remote that sends the message.
        /// <para>
        /// It can be the root local name, or a <see cref="TenantDomainParty"/> name.
        /// </para>
        /// </summary>
        public string DomainName => _domainName;

        /// <summary>
        /// Gets the party name: it is the <see cref="ILocalParty"/>'s <see cref="IParty.PartyName"/>
        /// of the remote that sends the message.
        /// <para>
        /// It can be the root local name, or a <see cref="TenantDomainParty"/> name.
        /// </para>
        /// </summary>
        public string PartyName => _partyName;

        /// <summary>
        /// Gets the environment name: it is the <see cref="ILocalParty"/>'s <see cref="IParty.EnvironmentName"/>
        /// of the remote that sends the message.
        /// <para>
        /// It can be the root local name, or a <see cref="TenantDomainParty"/> name.
        /// </para>
        /// </summary>
        public string EnvironmentName => _environmentName;

        /// <summary>
        /// Gets the party full name: it is the <see cref="ILocalParty"/> full name of
        /// the remote that sends the message.
        /// <para>
        /// It can be the root local name, or a <see cref="TenantDomainParty"/> full name.
        /// </para>
        /// </summary>
        public string FullName => _fullName;

        /// <summary>
        /// Gets the list of protocols with their versions that are supported.
        /// </summary>
        public IReadOnlyCollection<string> AvailableProtocols => _availableProtocols;

        /// <summary>
        /// Gets the list of public keys that identify this local party to the target.
        /// This is empty for an incoming message.
        /// </summary>
        public IReadOnlyList<LocalIdentityKey> LocalIdentities => _localIdentities;

        /// <summary>
        /// Gets the list of public keys that identify incoming message's party.
        /// This is empty for an outgoing message.
        /// </summary>
        public IReadOnlyList<RemoteIdentityKeyData> RemoteIdentities => _remoteIdentities;

        /// <summary>
        /// Incoming message only: contains the hash of the message (without the <see cref="Signatures"/>).
        /// </summary>
        public byte[]? HashMessage => _hashMessage;

        /// <summary>
        /// Incoming message only: contains the signatures for each <see cref="RemoteIdentities"/>.
        /// </summary>
        public byte[][]? Signatures => _signatures;
    }
}
