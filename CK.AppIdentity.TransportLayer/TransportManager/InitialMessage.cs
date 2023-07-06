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
        const int MaxPublicKeySize = 8 + ILocalKeys.MaxPublicKeySize; // TimeName (DateTime) + really enough size for ECDsa keys.
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
        // Local identities is empty for incoming message.
        readonly IReadOnlyList<LocalIdentityKey> _localIdentities;

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
        }

        /// <summary>
        /// Ingoing message constructor: the <see cref="RemoteIdentityKeyData"/> keys,
        /// the SHA1 hash of the data and the signatures for each key.
        /// </summary>
        public InitialMessage( string endPointDescription,
                               string remoteEndPointDescription,
                               int version,
                               string instanceId,
                               string incomingDomainName,
                               string incomingPartyName,
                               string incomingEnvironmentName,
                               string incomingFullName,
                               string[] protocols )
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
            _localIdentities = Array.Empty<LocalIdentityKey>();
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
        }

        /// <summary>
        /// Tries to parse the incoming initial message content (not the identity keys).
        /// This returns false if the message is not a message or the <paramref name="otherVersion"/>
        /// is greater that this <see cref="ZeroProtocol.CurrentVersion"/>.
        /// </summary>
        public static bool TryParse( ref FastByteReader r,
                                     out int otherVersion,
                                     [NotNullWhen( true )] out string? instanceId,
                                     [NotNullWhen( true )] out string? domainName,
                                     [NotNullWhen( true )] out string? partyName,
                                     [NotNullWhen( true )] out string? environmentName,
                                     [NotNullWhen( true )] out string? fullName,
                                     [NotNullWhen( true )] out string[]? protocols )
        {
            Span<byte> header = stackalloc byte[8];
            r.ReadBytes( header );
            if( !header.SequenceEqual( _prefix ) )
            {
                otherVersion = -1;
                return False( out instanceId, out domainName, out partyName, out environmentName, out fullName, out protocols );
            }
            // If the other's version is greater than ours we must reply with a
            // downgrade version message.
            otherVersion = checked((int)r.ReadSmallUInt32());
            if( otherVersion > ZeroProtocol.CurrentVersion )
            {
                return False( out instanceId, out domainName, out partyName, out environmentName, out fullName, out protocols );
            }
            // If a new protocol version appears, the previous versions should be handled here.
            // For now, we have only one version.
            instanceId = r.ReadString( InstanceIdMaxLength );
            Throw.CheckData( instanceId.Length > 3 );

            fullName = r.ReadString( CoreApplicationIdentity.FullNameMaxLength );
            Throw.CheckData( CoreApplicationIdentity.TryParseFullName( fullName, out domainName, out partyName, out environmentName )
                             && domainName != null && partyName != null && environmentName != null );

            var protocolCount = r.ReadSmallUInt32();
            Throw.CheckData( protocolCount <= MaxProtocolFullNameCount );
            protocols = new string[protocolCount];
            for( int i = 0; i < protocols.Length; i++ )
            {
                protocols[i] = r.ReadString( MessageProtocol.FullNameMaxLength );
            }
            return true;

            static bool False( out string? instanceId,
                               out string? domainName,
                               out string? partyName,
                               out string? environmentName,
                               out string? fullName,
                               out string[]? protocols )
            {
                instanceId = null;
                domainName = null;
                partyName = null;
                environmentName = null;
                fullName = null;
                protocols = null;
                return false;
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
    }
}
