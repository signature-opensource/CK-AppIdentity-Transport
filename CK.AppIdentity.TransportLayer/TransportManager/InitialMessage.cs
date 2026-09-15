using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Internal immutable initial message.
/// </summary>
sealed class InitialMessage : IIncomingRequest
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
                               + 5 // expectedCommonProtocolCount
                               + 1 // Is there a RemoteTrustInfo.SupposedIdentity?
                               + 1 // RemoteTrustInfo.CanAutoTrust?
                               + MaxPublicKeySize // The SupposedIdentity: TimeName + public key bytes.
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
    readonly RemoteIdentityKeyData? _supposedIdentity;
    readonly bool _canAutoTrust;
    readonly int _version;

    // Prefix is "CK-AppId" in ASCII.
    static ReadOnlySpan<byte> _prefix => "CK-AppId"u8;

    // For an outgoing message:
    // TransportFeature.AvailableProtocols is adapted: no concurrency issues here,
    // see TransportFeature.AvailableProtocols code comments.
    // For an ingoing message, this is an array.
    readonly IReadOnlyCollection<string> _availableProtocols;
    // The initiator BestRegisteredProtocols.Count: this is enough for the
    // listener to detect that he cannot satisfy the initiator.
    readonly int _expectedCommonProtocolCount;

    // Local identities is empty for incoming message.
    readonly IReadOnlyList<LocalIdentityKey> _localIdentities;

    // Relevant only for incoming messages.
    readonly RemoteIdentityKeyData? _currentRemoteIdentity;
    RemoteIdentityKey? _currentRemoteIdentityKey;
    readonly TimeSpan _clockOffset;
    readonly ulong _nonce;
    readonly bool _validClockOffset;

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
        Throw.DebugAssert( !f.IsListening );
        Throw.DebugAssert( f.RegisteredProtocols.Count <= MaxProtocolFullNameCount );
        var local = f.Party.Owner;
        _domainName = local.DomainName;
        _partyName = local.PartyName;
        _environmentName = local.EnvironmentName;
        _fullName = local.FullName;
        _instanceId = CoreApplicationIdentity.InstanceId;
        _supposedIdentity = f.RemoteKeys.TrustedIdentity?.GetKeyData();
        _canAutoTrust = f.RemoteKeys.AutoTrustKey == AutoTrustKey.Always
                        || (f.RemoteKeys.AutoTrustKey == AutoTrustKey.Once && _supposedIdentity == null);
        _endPointDescription = string.Empty;
        _remoteEndPointDescription = string.Empty;
        _availableProtocols = new ProtocolAdapter( f.RegisteredProtocols );
        _expectedCommonProtocolCount = f.BestRegisteredProtocols.Count;
        _localIdentities = f.RemoteKeys.LocalKeys.Identities;
    }

    /// <summary>
    /// Incoming message constructor.
    /// </summary>
    public InitialMessage( string endPointDescription,
                           string remoteEndPointDescription,
                           int version,
                           string instanceId,
                           string incomingDomainName,
                           string incomingPartyName,
                           string incomingEnvironmentName,
                           string incomingFullName,
                           string[] protocols,
                           int expectedCommonProtocolCount,
                           bool canAutoTrust,
                           RemoteIdentityKeyData? supposedIdentity,
                           ulong nonce,
                           bool validClockOffset,
                           TimeSpan clockOffset,
                           RemoteIdentityKeyData currentRemoteIdentity,
                           RemoteIdentityKey? currentRemoteIdentityKey )
    {
        _endPointDescription = endPointDescription;
        _remoteEndPointDescription = remoteEndPointDescription;
        _version = version;
        _instanceId = instanceId;
        _domainName = incomingDomainName;
        _partyName = incomingPartyName;
        _environmentName = incomingEnvironmentName;
        _fullName = incomingFullName;
        _availableProtocols = protocols;
        _expectedCommonProtocolCount = expectedCommonProtocolCount;
        _canAutoTrust = canAutoTrust;
        _supposedIdentity = supposedIdentity;
        _nonce = nonce;
        _validClockOffset = validClockOffset;
        _clockOffset = clockOffset;
        _currentRemoteIdentity = currentRemoteIdentity;
        _currentRemoteIdentityKey = currentRemoteIdentityKey;
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
        w.WriteSmallInt32( _expectedCommonProtocolCount );
        if( _supposedIdentity != null )
        {
            w.WriteBool( true );
            w.WriteDateTime( _supposedIdentity.TimeName );
            w.WriteSmallUInt32( (uint)_supposedIdentity.PublicKeyRawData.Length );
            w.WriteBytes( _supposedIdentity.PublicKeyRawData.Span );
        }
        else
        {
            w.WriteBool( false );
        }
        w.WriteBool( _canAutoTrust );
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
                                 [NotNullWhen( true )] out string[]? protocols,
                                 out int expectedCommonProtocolCount,
                                 out bool canAutoTrust,
                                 out RemoteIdentityKeyData? supposedIdentity )
    {
        Span<byte> header = stackalloc byte[8];
        r.ReadBytes( header );
        if( !header.SequenceEqual( _prefix ) )
        {
            otherVersion = -1;
            return False( out instanceId, out domainName, out partyName, out environmentName, out fullName, out protocols, out expectedCommonProtocolCount, out canAutoTrust, out supposedIdentity );
        }
        // If the other's version is greater than ours we must reply with a
        // downgrade version message.
        otherVersion = checked((int)r.ReadSmallUInt32());
        if( otherVersion > ZeroProtocol.CurrentVersion )
        {
            return False( out instanceId, out domainName, out partyName, out environmentName, out fullName, out protocols, out expectedCommonProtocolCount, out canAutoTrust, out supposedIdentity );
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
        expectedCommonProtocolCount = r.ReadSmallInt32();
        // Our SupposedIdentity known by the remote may not exist.
        if( r.ReadBool() )
        {
            var timeName = r.ReadDateTime();
            var lenKey = r.ReadSmallUInt32();
            Throw.CheckData( lenKey <= ILocalKeys.MaxPublicKeySize );
            if( !r.TryReadBytes( (int)lenKey, out var keyData  ) )
            {
                keyData = r.ReadBytes( lenKey );
            }
            var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo( keyData, out int bytesRead );
            Throw.CheckData( bytesRead == keyData.Length );
            supposedIdentity = new RemoteIdentityKeyData( timeName, publicKey );
        }
        else
        {
            supposedIdentity = null;
        }
        canAutoTrust = r.ReadBool();
        return true;

        static bool False( out string? instanceId,
                           out string? domainName,
                           out string? partyName,
                           out string? environmentName,
                           out string? fullName,
                           out string[]? protocols,
                           out int expectedCommonProtocolCount,
                           out bool canAutoTrust,
                           out RemoteIdentityKeyData? supposedIdentity )
        {
            instanceId = null;
            domainName = null;
            partyName = null;
            environmentName = null;
            fullName = null;
            protocols = null;
            expectedCommonProtocolCount = 0;
            canAutoTrust = false;
            supposedIdentity = null;
            return false;
        }
    }

    /// <inheritdoc />
    public int ZeroProtocolVersion => _version;

    /// <inheritdoc />
    /// <remarks>
    /// It's the empty string for an outgoing message.
    /// </remarks>
    public string IncomingEndPointDescription => _endPointDescription;

    /// <inheritdoc />
    /// <remarks>
    /// It's the empty string for an outgoing message.
    /// </remarks>
    public string RemoteEndPointDescription => _remoteEndPointDescription;

    /// <inheritdoc />
    /// <remarks>
    /// It's this <see cref="Core.CoreApplicationIdentity.InstanceId"/> for an outgoing message.
    /// </remarks>
    public string InstanceId => _instanceId;

    /// <inheritdoc />
    public string DomainName => _domainName;

    /// <inheritdoc />
    public string PartyName => _partyName;

    /// <inheritdoc />
    public string EnvironmentName => _environmentName;

    /// <inheritdoc />
    public string FullName => _fullName;

    /// <inheritdoc />
    public IReadOnlyCollection<string> AvailableProtocols => _availableProtocols;

    public int ExpectedCommonProtocolCount => _expectedCommonProtocolCount;

    /// <summary>
    /// Gets the list of public keys that identify this local party.
    /// This is empty for an incoming message.
    /// </summary>
    public IReadOnlyList<LocalIdentityKey> LocalIdentities => _localIdentities;

    /// <summary>
    /// Gets the remote identity that the initiator expects the listener to be and whether it can accept
    /// the .
    /// A null implies that the initiator doesn't trust its remote and is expecting to be peered.
    /// </summary>
    public (RemoteIdentityKeyData? SupposedIdentity, bool CanAutoTrust) RemoteTrustInfo => (_supposedIdentity, _canAutoTrust);

    /// <summary>
    /// Relevant only for incoming messages.
    /// </summary>
    public TimeSpan ClockOffset => _clockOffset;

    /// <summary>
    /// Relevant only for incoming messages.
    /// This is always false if the remote has not been resolved (<see cref="PeeringIssueKind.IncomingUnknwon"/>
    /// or <see cref="PeeringIssueKind.IncomingDisallowedTransport"/>). 
    /// </summary>
    public bool IsValidClockOffset => _validClockOffset;

    /// <summary>
    /// Relevant only for incoming messages.
    /// </summary>
    public ulong Nonce => _nonce;

    /// <summary>
    /// Relevant only for incoming messages.
    /// </summary>
    internal RemoteIdentityKey GetCurrentRemoteIdentityKey()
    {
        Throw.DebugAssert( "Called only from the IncomingConnectionBackTask.", _currentRemoteIdentity != null );
        if( _currentRemoteIdentityKey == null )
        {
            _currentRemoteIdentityKey = new RemoteIdentityKey( _currentRemoteIdentity );
        }
        return _currentRemoteIdentityKey;
    }

    /// <summary>
    /// Relevant only for incoming messages.
    /// </summary>
    internal RemoteIdentityKeyData GetCurrentRemoteIdentityKeyData()
    {
        Throw.DebugAssert( "Called only from the IncomingConnectionBackTask.", _currentRemoteIdentity != null );
        return _currentRemoteIdentity;
    }

    RemoteIdentityKeyData IIncomingRequest.CurrentRemoteIdentity
    {
        get
        {
            Throw.DebugAssert( "Called only from public IIncomingRequest facade.", _currentRemoteIdentity != null );
            return _currentRemoteIdentity;
        }
    }
}
