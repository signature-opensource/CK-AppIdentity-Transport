using CK.AppIdentity.KeyManagement;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace CK.AppIdentity.TransportLayer.Testing.Adversarial;

/// <summary>
/// The harness's own view of an <c>InitialMessage</c> as it appears on the wire.
/// <para>
/// The production <c>InitialMessage</c> type is internal, so this is an independent parser written
/// from the wire layout of <c>InitialMessage.WriteCurrentVersion</c> plus the nonce and the
/// identity block appended by <c>ZeroProtocol.WriteIdentityBlockAndSign</c>.
/// </para>
/// </summary>
public sealed class PeerInitialMessage
{
    /// <summary>The 8-byte magic that opens every initial message.</summary>
    public static ReadOnlySpan<byte> Prefix => "CK-AppId"u8;

    public required int Version { get; init; }
    public required string InstanceId { get; init; }
    public required string FullName { get; init; }
    public required IReadOnlyList<string> AvailableProtocols { get; init; }
    public required int ExpectedCommonProtocolCount { get; init; }

    public required bool CanAutoTrust { get; init; }

    /// <summary>
    /// The initiator's per-connection ephemeral ECDH public key: one half of the run-phase key
    /// agreement that protects every frame after the handshake.
    /// </summary>
    public required byte[] EphemeralPublicKey { get; init; }

    /// <summary>The MAC primitives the initiator can run, as a capability bit set.</summary>
    public required byte MacCapabilities { get; init; }

    /// <summary>
    /// What the initiator states about the certificate it is presenting: the SHA-256 of its DER, or
    /// null when it presents none — which is every cleartext connection.
    /// </summary>
    public byte[]? CertificateBinding { get; init; }

    /// <summary>Creation time of the timed nonce (used by the peer to compute the clock offset).</summary>
    public required DateTime NonceCreationTime { get; init; }

    /// <summary>The 64-bit nonce. Every reply in this negotiation must echo it.</summary>
    public required ulong Nonce { get; init; }

    /// <summary>The tail of the initiator's key event log, oldest first. The last one is its head.</summary>
    public required IReadOnlyList<KeyEvent> Tail { get; init; }

    /// <summary>What the initiator pins for us, when it pins something.</summary>
    public PeerStatement? Statement { get; init; }

    /// <summary>The signature, by the key the head of <see cref="Tail"/> reveals.</summary>
    public required byte[] Signature { get; init; }

    /// <summary>The head of the initiator's log.</summary>
    public KeyEvent Head => Tail[^1];

    public override string ToString()
        => $"InitialMessage from '{FullName}' (v{Version}, {AvailableProtocols.Count} protocols, " +
           $"head #{Head.Seq}, nonce {Nonce:X16})";

    /// <summary>
    /// Parses an initial message payload (the frame payload, without the wire header).
    /// Throws when the payload is not a well-formed initial message.
    /// </summary>
    public static PeerInitialMessage Parse( ReadOnlyMemory<byte> payload )
    {
        var r = new FastByteReader( new ReadOnlySequence<byte>( payload ) );

        Span<byte> prefix = stackalloc byte[8];
        r.ReadBytes( prefix );
        if( !prefix.SequenceEqual( Prefix ) )
        {
            throw new InvalidOperationException(
                $"Not an InitialMessage: expected prefix '{Encoding.ASCII.GetString( Prefix )}', " +
                $"got '{Encoding.ASCII.GetString( prefix )}'." );
        }
        int version = (int)r.ReadSmallUInt32();
        var instanceId = r.ReadString();
        var fullName = r.ReadString();
        uint protocolCount = r.ReadSmallUInt32();
        var protocols = new string[protocolCount];
        for( int i = 0; i < protocolCount; ++i ) protocols[i] = r.ReadString();
        int expectedCommon = r.ReadSmallInt32();
        bool canAutoTrust = r.ReadBool();

        // Per-connection key agreement material, written inside the signed region right after the
        // cached message content and before the nonce.
        uint lenEphemeral = r.ReadSmallUInt32();
        var ephemeral = r.ReadBytes( lenEphemeral );
        byte macCaps = r.ReadByte();

        // What the initiator states about the certificate it presented, still inside the signed
        // region: length then bytes, 0 meaning none.
        uint lenBinding = r.ReadSmallUInt32();
        var certificateBinding = lenBinding == 0 ? null : r.ReadBytes( lenBinding );

        // The timed nonce.
        var nonceTime = r.ReadDateTime();
        ulong nonce = r.ReadUInt64();

        // The identity block has its own serialization version.
        uint identityBlockVersion = r.ReadSmallUInt32();
        if( identityBlockVersion != 0 )
        {
            throw new InvalidOperationException( $"Unexpected identity block version {identityBlockVersion}." );
        }
        uint eventCount = r.ReadSmallUInt32();
        var tail = new KeyEvent[eventCount];
        for( int i = 0; i < eventCount; ++i )
        {
            uint len = r.ReadSmallUInt32();
            tail[i] = KeyEvent.Read( r.ReadBytes( len ) );
        }
        PeerStatement? statement = null;
        uint stated = r.ReadSmallUInt32();
        if( stated != 0 ) statement = new PeerStatement( (int)(stated - 1), r.ReadBytes( KeyEvent.HashSize ) );
        byte sigLen = r.ReadByte();
        var signature = r.ReadBytes( sigLen );

        return new PeerInitialMessage
        {
            Version = version,
            InstanceId = instanceId,
            FullName = fullName,
            AvailableProtocols = protocols,
            ExpectedCommonProtocolCount = expectedCommon,
            CanAutoTrust = canAutoTrust,
            EphemeralPublicKey = ephemeral,
            MacCapabilities = macCaps,
            CertificateBinding = certificateBinding,
            NonceCreationTime = nonceTime,
            Nonce = nonce,
            Tail = tail,
            Statement = statement,
            Signature = signature
        };
    }
}
