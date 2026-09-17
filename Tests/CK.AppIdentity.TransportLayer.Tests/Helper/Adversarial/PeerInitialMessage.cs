using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace CK.AppIdentity.TransportLayer.Tests.Adversarial;

/// <summary>
/// The harness's own view of an <c>InitialMessage</c> as it appears on the wire.
/// <para>
/// The production <c>InitialMessage</c> type is internal, so this is an independent parser written
/// from the wire layout of <c>InitialMessage.WriteCurrentVersion</c> plus the nonce and the
/// identity/signature block appended by <c>ZeroProtocol.WriteIdentityKeysAndSign</c>.
/// </para>
/// </summary>
sealed class PeerInitialMessage
{
    /// <summary>The 8-byte magic that opens every initial message.</summary>
    public static ReadOnlySpan<byte> Prefix => "CK-AppId"u8;

    public required int Version { get; init; }
    public required string InstanceId { get; init; }
    public required string FullName { get; init; }
    public required IReadOnlyList<string> AvailableProtocols { get; init; }
    public required int ExpectedCommonProtocolCount { get; init; }

    /// <summary>The key the initiator believes we hold, when it has one.</summary>
    public PeerPublicKey? SupposedIdentity { get; init; }
    public required bool CanAutoTrust { get; init; }

    /// <summary>Creation time of the timed nonce (used by the peer to compute the clock offset).</summary>
    public required DateTime NonceCreationTime { get; init; }

    /// <summary>The 64-bit nonce. Every reply in this negotiation must echo it.</summary>
    public required ulong Nonce { get; init; }

    /// <summary>The initiator's identity keys, most recent first.</summary>
    public required IReadOnlyList<PeerPublicKey> Identities { get; init; }

    /// <summary>One signature per entry of <see cref="Identities"/>.</summary>
    public required IReadOnlyList<byte[]> Signatures { get; init; }

    public override string ToString()
        => $"InitialMessage from '{FullName}' (v{Version}, {AvailableProtocols.Count} protocols, " +
           $"{Identities.Count} identities, nonce {Nonce:X16})";

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

        PeerPublicKey? supposed = null;
        if( r.ReadBool() ) supposed = ReadKey( ref r );
        bool canAutoTrust = r.ReadBool();

        // The timed nonce.
        var nonceTime = r.ReadDateTime();
        ulong nonce = r.ReadUInt64();

        // The identity block has its own serialization version.
        uint identityBlockVersion = r.ReadSmallUInt32();
        if( identityBlockVersion != 0 )
        {
            throw new InvalidOperationException( $"Unexpected identity block version {identityBlockVersion}." );
        }
        uint keyCount = r.ReadSmallUInt32();
        var identities = new PeerPublicKey[keyCount];
        for( int i = 0; i < keyCount; ++i ) identities[i] = ReadKey( ref r );

        // One signature per identity, each length-prefixed by a single byte.
        var signatures = new byte[keyCount][];
        for( int i = 0; i < keyCount; ++i )
        {
            byte len = r.ReadByte();
            signatures[i] = r.ReadBytes( len );
        }

        return new PeerInitialMessage
        {
            Version = version,
            InstanceId = instanceId,
            FullName = fullName,
            AvailableProtocols = protocols,
            ExpectedCommonProtocolCount = expectedCommon,
            SupposedIdentity = supposed,
            CanAutoTrust = canAutoTrust,
            NonceCreationTime = nonceTime,
            Nonce = nonce,
            Identities = identities,
            Signatures = signatures
        };

        static PeerPublicKey ReadKey( ref FastByteReader r )
        {
            var timeName = r.ReadDateTime();
            uint len = r.ReadSmallUInt32();
            return new PeerPublicKey( timeName, r.ReadBytes( len ) );
        }
    }
}

/// <summary>
/// A public identity key as it travels on the wire: a creation time ("TimeName") and the
/// SubjectPublicKeyInfo raw bytes.
/// </summary>
sealed record PeerPublicKey( DateTime TimeName, byte[] SubjectPublicKeyInfo );
