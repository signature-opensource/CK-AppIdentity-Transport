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

    /// <summary>
    /// The maximal number of route names the initiator states that it hosts.
    /// </summary>
    public const int MaxHostedRouteCount = 16;

    /// <summary>
    /// The maximal length of a route name stated by the initiator.
    /// </summary>
    public const int MaxRouteNameLength = 64;
    // Used as a high limit so that weirdly big messages are just skipped.
    // Note that each string or array read are also protected.
    public const int MaxLength = 8 // "CK-AppId"
                               + 5 // Version (allows uint.MaxValue)
                               + (1 + InstanceIdMaxLength) // InstanceId
                               + (2 + CoreApplicationIdentity.FullNameMaxLength) // Party' FullName
                               + 5 // Number of protocol names (allows uint.MaxValue)
                               + MaxProtocolFullNameCount * (2 + MessageProtocol.FullNameMaxLength)
                               + 5 // expectedCommonProtocolCount
                               + 1 // RemoteTrustInfo.CanAutoTrust?
                               + 5 + MaxHostedRouteCount * (2 + MaxRouteNameLength) // The names of the routes the initiator hosts.
                               + (5 + RunPhaseProtection.MaxEphemeralPublicKeyLength) // The initiator's ephemeral ECDH public key.
                               + (5 + AnchoredStatement.MaxEncodedSize) // The pin grant the initiator holds for the listener.
                               + 1 // Its MAC capabilities.
                               + ApprovalSession.NonceLength // The commitment to its nonce of the approval code.
                               + (5 + Transport.CertificateBindingLength) // What it states about the certificate it presents.
                               + 8 + 8 // The timed nonce: creation time and value.
                               + ZeroProtocol.IdentityBlockMaxLength;
    readonly string _endPointDescription;
    readonly string _remoteEndPointDescription;
    readonly string _domainName;
    readonly string _partyName;
    readonly string _environmentName;
    readonly string _fullName;
    readonly string _instanceId;
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

    // Relevant only for incoming messages: what the initiator's identity block said.
    readonly IdentityBlock _block;
    RemoteIdentityKey? _currentRemoteIdentityKey;
    readonly TimeSpan _clockOffset;
    readonly ulong _nonce;
    readonly bool _validClockOffset;
    // The initiator's per-connection ECDH public key and the MAC primitives it can run.
    // Incoming only: on the outgoing side these belong to the Transport, because this object is
    // cached on the TransportFeature and reused across connection attempts.
    readonly byte[] _remoteEphemeralPublicKey;
    readonly byte _remoteMacCapabilities;
    // Incoming only: the initiator's commitment to its nonce of the approval code (see ApprovalSession).
    readonly byte[] _approvalCommitment;
    // Outgoing: the local party (its hosted routes are read when the message is written). Incoming: the names of the
    // routes the initiator states that it hosts (a party waiting for its approval: the operator authorizes them with it).
    readonly ILocalParty? _local;
    readonly string[] _hostedRoutes;

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
        // A real check: compiled out, an over-count would be written on the wire and refused by the
        // peer, which is a configuration mistake discovered at the far end of a handshake.
        Throw.CheckState( f.RegisteredProtocols.Count <= MaxProtocolFullNameCount );
        var local = f.Party.Owner;
        _domainName = local.DomainName;
        _partyName = local.PartyName;
        _environmentName = local.EnvironmentName;
        _fullName = local.FullName;
        _instanceId = CoreApplicationIdentity.InstanceId;
        _canAutoTrust = (f.RemoteKeys.AutoTrustKey == AutoTrustKey.Once || f.RemoteKeys.IsAnchored) && f.RemoteKeys.TrustedEvent == null;
        _endPointDescription = string.Empty;
        _remoteEndPointDescription = string.Empty;
        _availableProtocols = new ProtocolAdapter( f.RegisteredProtocols );
        _expectedCommonProtocolCount = f.BestRegisteredProtocols.Count;
        // Outgoing: the ephemeral belongs to the Transport, not here — this object is cached and
        // reused across connection attempts, and a reused ephemeral would reuse the session key.
        _remoteEphemeralPublicKey = Array.Empty<byte>();
        _approvalCommitment = Array.Empty<byte>();
        _local = local;
        _hostedRoutes = [];
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
                           ulong nonce,
                           bool validClockOffset,
                           TimeSpan clockOffset,
                           IdentityBlock block,
                           byte[] remoteEphemeralPublicKey,
                           byte remoteMacCapabilities,
                           byte[] approvalCommitment,
                           string[] hostedRoutes )
    {
        _hostedRoutes = hostedRoutes;
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
        _nonce = nonce;
        _validClockOffset = validClockOffset;
        _clockOffset = clockOffset;
        _block = block;
        _remoteEphemeralPublicKey = remoteEphemeralPublicKey;
        _remoteMacCapabilities = remoteMacCapabilities;
        _approvalCommitment = approvalCommitment;
    }

    /// <summary>
    /// Gets the initiator's commitment to its nonce of the approval code (incoming messages only).
    /// </summary>
    internal byte[] ApprovalCommitment => _approvalCommitment;

    /// <summary>
    /// Gets the initiator's ephemeral ECDH public key (incoming messages only).
    /// </summary>
    public ReadOnlySpan<byte> RemoteEphemeralPublicKey => _remoteEphemeralPublicKey;

    /// <summary>
    /// Gets the MAC primitives the initiator can run (incoming messages only).
    /// </summary>
    public byte RemoteMacCapabilities => _remoteMacCapabilities;

    /// <summary>
    /// Gets the names of the routes the initiator hosts: read from the local party for an outgoing message (when it is
    /// written), the ones it stated for an incoming one.
    /// </summary>
    public IReadOnlyList<string> HostedRoutes => _local != null ? GetHostedRoutes( _local ) : _hostedRoutes;

    static string[] GetHostedRoutes( ILocalParty local )
    {
        string self = local.FullName;
        return local.Description.Routes
                    .Where( kv => kv.Key.Length <= MaxRouteNameLength && kv.Value.Any( r => r.Host == self ) )
                    .Select( kv => kv.Key )
                    .Take( MaxHostedRouteCount )
                    .ToArray();
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
        w.WriteBool( _canAutoTrust );
        // The routes this party hosts: when it waits for its approval, the operator authorizes them with it.
        var hosted = HostedRoutes;
        w.WriteSmallUInt32( (uint)hosted.Count );
        foreach( var name in hosted ) w.WriteString( name );
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
                                 [NotNullWhen( true )] out string[]? hostedRoutes )
    {
        hostedRoutes = null;
        Span<byte> header = stackalloc byte[8];
        r.ReadBytes( header );
        if( !header.SequenceEqual( _prefix ) )
        {
            otherVersion = -1;
            return False( out instanceId, out domainName, out partyName, out environmentName, out fullName, out protocols, out expectedCommonProtocolCount, out canAutoTrust );
        }
        // If the other's version is greater than ours we must reply with a
        // downgrade version message.
        // An over-range varint here used to raise OverflowException, which ConnectionFault does not
        // classify as a peer fault: a few garbage bytes per connection produced a full-stack Error
        // with ToBeInvestigated. It is malformed input from an unauthenticated peer, nothing more.
        uint declaredVersion = r.ReadSmallUInt32();
        Throw.CheckData( declaredVersion <= int.MaxValue );
        otherVersion = (int)declaredVersion;
        if( otherVersion > ZeroProtocol.CurrentVersion )
        {
            return False( out instanceId, out domainName, out partyName, out environmentName, out fullName, out protocols, out expectedCommonProtocolCount, out canAutoTrust );
        }
        // If a new protocol version appears, the previous versions should be handled here.
        // For now, we have only one version.
        instanceId = r.ReadString( InstanceIdMaxLength );
        // Charset validated HERE, at parse time. GoodbyeMessage.Evicted requires Base64Url characters
        // and its constructor runs after a completed handshake, so a non-conforming id used to throw
        // at the very last step - after the full ECDSA cost had been paid.
        Throw.CheckData( instanceId.Length > 3 && Base64UrlHelper.IsBase64UrlCharacters( instanceId ) );

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
        canAutoTrust = r.ReadBool();
        var hostedCount = r.ReadSmallUInt32();
        Throw.CheckData( hostedCount <= MaxHostedRouteCount );
        hostedRoutes = new string[hostedCount];
        for( int i = 0; i < hostedRoutes.Length; i++ )
        {
            hostedRoutes[i] = r.ReadString( MaxRouteNameLength );
            Throw.CheckData( PartyDescription.IsValidName( hostedRoutes[i] ) );
        }
        return true;

        static bool False( out string? instanceId,
                           out string? domainName,
                           out string? partyName,
                           out string? environmentName,
                           out string? fullName,
                           out string[]? protocols,
                           out int expectedCommonProtocolCount,
                           out bool canAutoTrust )
        {
            instanceId = null;
            domainName = null;
            partyName = null;
            environmentName = null;
            fullName = null;
            protocols = null;
            expectedCommonProtocolCount = 0;
            canAutoTrust = false;
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
    /// Gets the sequence of our key event log the initiator pins for us (null when it pins nothing)
    /// and whether it can trust us automatically. Relevant only for incoming messages.
    /// </summary>
    public (int? PinnedSeq, bool CanAutoTrust) RemoteTrustInfo => (_block.StatedSeq, _canAutoTrust);

    /// <summary>
    /// Gets the digest of the event the initiator pins for us, when <see cref="RemoteTrustInfo"/> says
    /// it pins one. Relevant only for incoming messages.
    /// </summary>
    internal byte[]? PinnedDigest => _block.StatedDigest;

    /// <summary>
    /// Gets the head of the key event log the initiator presented. Relevant only for incoming messages.
    /// </summary>
    internal KeyEvent RemoteHead => _block.Head;

    /// <summary>
    /// Gets the initiator's operational key, when its credential and signature verified. Relevant only for incoming messages.
    /// </summary>
    internal System.Security.Cryptography.ECDsa? RemoteOperationalKey => _block.OperationalKey;

    /// <summary>
    /// Gets the expiry of the initiator's operational credential (UTC). Relevant only for incoming messages.
    /// </summary>
    internal DateTime RemoteCredentialNotAfter => _block.CredentialNotAfter;

    /// <summary>
    /// Relevant only for incoming messages.
    /// </summary>
    public TimeSpan ClockOffset => _clockOffset;

    /// <summary>
    /// Relevant only for incoming messages.
    /// This is always false if the remote has not been resolved (<see cref="PeeringIssueKind.IncomingUnknown"/>
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
        Throw.DebugAssert( "Called only from the IncomingConnectionBackTask.", _block.Head != null );
        return _currentRemoteIdentityKey ??= new RemoteIdentityKey( _block.HeadKeyData );
    }

    /// <summary>
    /// Relevant only for incoming messages.
    /// </summary>
    internal RemoteIdentityKeyData GetCurrentRemoteIdentityKeyData()
    {
        Throw.DebugAssert( "Called only from the IncomingConnectionBackTask.", _block.Head != null );
        return _block.HeadKeyData;
    }

    RemoteIdentityKeyData IIncomingRequest.CurrentRemoteIdentity
    {
        get
        {
            Throw.DebugAssert( "Called only from public IIncomingRequest facade.", _block.Head != null );
            return _block.HeadKeyData;
        }
    }
}
