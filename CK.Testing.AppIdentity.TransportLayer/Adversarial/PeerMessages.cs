using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using CK.AppIdentity.KeyManagement;

namespace CK.AppIdentity.TransportLayer.Testing.Adversarial;

/// <summary>
/// Builds Zero Protocol reply payloads for the adversarial peer.
/// <para>
/// Independent of the production writers (which are internal anyway), so the harness can emit
/// messages the production code would never emit: signed by the wrong key, echoing a stale nonce,
/// carrying an oversized field. Every builder takes its signing identities explicitly — that
/// parameter is the knob each C2 test turns.
/// </para>
/// </summary>
public static class PeerMessages
{
    /// <summary>Writes a message body. A delegate taking <c>ref</c> because FastByteWriter is a ref struct.</summary>
    public delegate void BodyWriter( ref FastByteWriter w );

    // Discriminators, mirroring the internal ZeroProtocol constants.
    public const byte DNegoRejectRemote = 0;
    public const byte DNegoFinalFailureMessage = 1;
    public const byte DNegoDowngradeProtocol = 2;
    public const byte DNegoAcceptedProtocolsMessage = 3;
    public const byte DNegoMissingProtocols = 4;
    public const byte DNegoEvictionDisallowed = 5;
    public const byte DNegoOffRemote = 6;
    public const byte DNegoFinalSuccessMessage = 7;
    public const byte DNegoRequiredEnlistUrl = 8;
    public const byte DRunGoodbye = 255;

    // GoodbyeMessage discriminators (GoodbyeMessage.WriteMessage).
    public const byte GoodbyeEvicted = 0;
    public const byte GoodbyeSwitchedOff = 1;
    public const byte GoodbyePartyDestroyed = 2;
    public const byte GoodbyeApplicationIdentityShutdown = 3;

    /// <summary>
    /// The initiator's opening message, for driving a REAL listener.
    /// <para>
    /// Everything here is attacker-chosen, including <paramref name="fullName"/>: the listener
    /// resolves the remote party by the claimed name and only afterwards asks whether the
    /// signature means anything.
    /// </para>
    /// </summary>
    /// <param name="fullName">The claimed party name, in its full form, e.g. "Test/$Init/#Dev".</param>
    /// <param name="nonceCreationTime">Nonce timestamp: the listener derives the clock offset from it.</param>
    /// <param name="nonce">The 64-bit nonce. Reusing one is what the replay cache must catch.</param>
    public static byte[] InitialMessage( string fullName,
                                         string instanceId,
                                         IReadOnlyList<string> availableProtocols,
                                         int expectedCommonProtocolCount,
                                         DateTime nonceCreationTime,
                                         ulong nonce,
                                         byte[] ephemeralPublicKey,
                                         byte macCapabilities,
                                         PeerIdentity signWith,
                                         PeerStatement? statement = null,
                                         bool canAutoTrust = false,
                                         byte[]? certificateBinding = null,
                                         byte[]? approvalCommitment = null )
    {
        // The commitment to a nonce of the approval code: a random one when none is given.
        approvalCommitment ??= System.Security.Cryptography.RandomNumberGenerator.GetBytes( 32 );
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteBytes( PeerInitialMessage.Prefix );
            w.WriteSmallUInt32( 0 );                      // ZeroProtocol.CurrentVersion
            w.WriteString( instanceId );
            w.WriteString( fullName );
            w.WriteSmallUInt32( (uint)availableProtocols.Count );
            foreach( var p in availableProtocols ) w.WriteString( p );
            w.WriteSmallInt32( expectedCommonProtocolCount );
            w.WriteBool( canAutoTrust );
            // The names of the routes it hosts: none.
            w.WriteSmallUInt32( 0 );
            // Per-connection key agreement material, inside the signed region.
            w.WriteSmallUInt32( (uint)ephemeralPublicKey.Length );
            w.WriteBytes( ephemeralPublicKey );
            w.WriteByte( macCapabilities );
            // The commitment to its nonce of the approval code, inside the signed region.
            w.WriteBytes( approvalCommitment );
            // No pin grant (an optional statement: length then bytes, 0 meaning none).
            w.WriteSmallUInt32( 0 );
            // What this side states about the certificate it is presenting, inside the signed region.
            WriteCertificateBinding( ref w, certificateBinding );
            // The timed nonce.
            w.WriteDateTime( nonceCreationTime );
            w.WriteUInt64( nonce );
        }, signWith, statement );
    }

    /// <summary>
    /// The listener's success reply: the negotiated protocol list, signed.
    /// </summary>
    /// <param name="nonce">Must echo the initiator's nonce.</param>
    /// <param name="initialClockOffset">The offset the peer computed from the initiator's nonce time.</param>
    /// <param name="now">The peer's current time (the initiator finishes the clock-offset calculation with it).</param>
    /// <param name="protocolFullNames">The accepted protocols, as "Name.Version".</param>
    /// <param name="signWith">The identity presented and signing.</param>
    public static byte[] AcceptedProtocols( ulong nonce,
                                            TimeSpan initialClockOffset,
                                            DateTime now,
                                            IReadOnlyList<string> protocolFullNames,
                                            byte[] ephemeralPublicKey,
                                            MacAlgorithm macAlgorithm,
                                            PeerIdentity signWith,
                                            byte[]? certificateBinding = null,
                                            byte? macCapabilities = null,
                                            PeerStatement? statement = null )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoAcceptedProtocolsMessage );
            w.WriteUInt64( nonce );
            w.WriteTimeSpan( initialClockOffset );
            w.WriteDateTime( now );
            w.WriteSmallUInt32( (uint)protocolFullNames.Count );
            foreach( var p in protocolFullNames ) w.WriteString( p );
            // The listener's half of the key agreement plus its selection.
            w.WriteSmallUInt32( (uint)ephemeralPublicKey.Length );
            w.WriteBytes( ephemeralPublicKey );
            w.WriteByte( (byte)macAlgorithm );
            // The listener's own capability byte, inside the signed region. Defaults to "exactly the
            // selected algorithm", which is the honest answer for a harness that offers only what it
            // just chose - a test that wants to claim more (or lie) passes its own value.
            w.WriteByte( macCapabilities ?? (byte)(1 << (int)macAlgorithm) );
            // What this side states about the certificate it is presenting, inside the signed region.
            WriteCertificateBinding( ref w, certificateBinding );
        }, signWith, statement );
    }

    /// <summary>
    /// Writes the certificate binding field: length then bytes, a length of 0 meaning that this side
    /// presents no certificate. One byte on a cleartext connection.
    /// </summary>
    static void WriteCertificateBinding( ref FastByteWriter w, byte[]? binding )
    {
        w.WriteSmallUInt32( (uint)(binding?.Length ?? 0) );
        if( binding != null ) w.WriteBytes( binding );
    }

    /// <summary>
    /// The usual success reply: echoes the initiator's nonce, accepts exactly the protocols it
    /// offered, and completes the key agreement with a fresh ephemeral and the strongest MAC both
    /// sides can run.
    /// </summary>
    /// <param name="initial">The initial message being answered.</param>
    /// <param name="now">Our current time.</param>
    /// <param name="signWith">The identity presented and signing — the knob the C2 tests turn.</param>
    /// <param name="ephemeral">
    /// Our ephemeral key pair. A fresh one is created when null; a test passes an existing one to
    /// REUSE it across connections, which a real peer never does.
    /// </param>
    /// <param name="certificateBinding">
    /// What to state about the certificate we are presenting. Null is the truth on a cleartext
    /// connection; anything else is the claim a relay would have to make.
    /// </param>
    public static byte[] AcceptedProtocols( PeerInitialMessage initial,
                                            DateTime now,
                                            PeerIdentity signWith,
                                            PeerEphemeral? ephemeral = null,
                                            byte[]? certificateBinding = null,
                                            byte? macCapabilities = null,
                                            PeerStatement? statement = null )
    {
        bool owned = ephemeral == null;
        ephemeral ??= new PeerEphemeral();
        try
        {
            return AcceptedProtocols( initial.Nonce,
                                      TimeSpan.Zero,
                                      now,
                                      initial.AvailableProtocols,
                                      ephemeral.PublicKey,
                                      RunPhaseProtection.Select( initial.MacCapabilities ),
                                      signWith,
                                      certificateBinding,
                                      macCapabilities ?? RunPhaseProtection.LocalCapabilities,
                                      statement );
        }
        finally
        {
            if( owned ) ephemeral.Dispose();
        }
    }

    /// <summary>
    /// "Your remote is switched off." The message finding C2's first failure scenario abuses: if a
    /// reader accepts one of these signed by any key at all, it takes a remote down for good.
    /// </summary>
    /// <param name="expectedAvailableTime">
    /// When the peer expects to be back. <see cref="DateTime.MaxValue"/> in UTC means "never" and
    /// switches the remote off permanently.
    /// </param>
    public static byte[] OffRemote( ulong nonce,
                                    TimeSpan clockOffset,
                                    string reason,
                                    DateTime? expectedAvailableTime,
                                    PeerIdentity signWith,
                                           PeerStatement? statement = null )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoOffRemote );
            w.WriteUInt64( nonce );
            w.WriteTimeSpan( clockOffset );
            w.WriteBool( true );                 // a GoodbyeMessage follows
            w.WriteByte( GoodbyeSwitchedOff );
            w.WriteString( reason );
            w.WriteNullableDateTime( expectedAvailableTime );
        }, signWith, statement );
    }

    /// <summary>
    /// The listener refuses the connection, with a reason and an optional enlistment URL.
    /// </summary>
    /// <param name="signWith">
    /// Null produces the legitimately unsigned form (the listener has no local keys when it does
    /// not know the party at all).
    /// </param>
    public static byte[] RejectRemote( ulong nonce,
                                       byte issue,
                                       TimeSpan? clockOffset,
                                       string? enlistUrl,
                                       PeerIdentity? signWith,
                                       PeerStatement? statement = null,
                                       byte[]? approvalNonce = null )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoRejectRemote );
            w.WriteUInt64( nonce );
            w.WriteByte( issue );
            w.WriteNullableTimeSpan( clockOffset );
            w.WriteString( enlistUrl ?? string.Empty );
            // The listener's nonce of the approval code (the approval issues only): length then bytes.
            w.WriteSmallUInt32( (uint)(approvalNonce?.Length ?? 0) );
            if( approvalNonce != null ) w.WriteBytes( approvalNonce );
            // No enlistment URL statement, no pin grant (optional statements: length then bytes, 0 meaning none).
            w.WriteSmallUInt32( 0 );
            w.WriteSmallUInt32( 0 );
            // The bool says whether an identity block follows.
            w.WriteBool( signWith != null );
        }, signWith, statement );
    }

    /// <summary>
    /// The initiator's FinalSuccess: the nonce, the final clock offset and the SHA-256 of the listener's ephemeral public
    /// key of this connection (the key confirmation), signed by the operational key of <paramref name="signWith"/>.
    /// </summary>
    /// <param name="listenerEphemeralPublicKey">
    /// The listener's ephemeral public key to confirm, or null to write the message without confirmation (what a
    /// FinalSuccess was before it confirmed its connection).
    /// </param>
    public static byte[] FinalSuccess( ulong nonce, TimeSpan finalClockOffset, byte[]? listenerEphemeralPublicKey, PeerIdentity signWith )
    {
        using var seq = new MutableSequence<byte>();
        var w = new FastByteWriter( seq );
        w.WriteByte( DNegoFinalSuccessMessage );
        w.WriteUInt64( nonce );
        w.WriteTimeSpan( finalClockOffset );
        if( listenerEphemeralPublicKey != null ) w.WriteBytes( SHA256.HashData( listenerEphemeralPublicKey ) );
        w.Commit();
        Span<byte> hash = stackalloc byte[64];
        ComputeSha512( seq, hash );
        var sig = signWith.Credential.Key.SignHash( hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
        w.WriteByte( (byte)sig.Length );
        w.WriteBytes( sig );
        w.Commit();
        return seq.GetReadOnlySequence().ToArray();
    }

    /// <summary>
    /// Reads the listener's nonce of the approval code from its RejectRemote message (null when it sent none).
    /// </summary>
    public static byte[]? ReadApprovalNonce( byte[] rejectRemote )
    {
        var r = new FastByteReader( new ReadOnlySequence<byte>( rejectRemote ) );
        if( r.ReadByte() != DNegoRejectRemote ) throw new InvalidOperationException( "Not a RejectRemote message." );
        r.ReadUInt64();
        r.ReadByte();
        r.ReadNullableTimeSpan();
        r.ReadString();
        uint length = r.ReadSmallUInt32();
        return length == 0 ? null : r.ReadBytes( length );
    }

    /// <summary>
    /// Reads the listener's ephemeral public key from its AcceptedProtocols message.
    /// </summary>
    public static byte[] ReadListenerEphemeral( byte[] acceptedProtocols )
    {
        var r = new FastByteReader( new ReadOnlySequence<byte>( acceptedProtocols ) );
        if( r.ReadByte() != DNegoAcceptedProtocolsMessage ) throw new InvalidOperationException( "Not an AcceptedProtocols message." );
        r.ReadUInt64();
        r.ReadTimeSpan();
        r.ReadDateTime();
        uint count = r.ReadSmallUInt32();
        for( int i = 0; i < count; ++i ) r.ReadString();
        return r.ReadBytes( r.ReadSmallUInt32() );
    }

    /// <summary>
    /// The listener refuses to be evicted by this new connection.
    /// </summary>
    public static byte[] EvictionDisallowed( ulong nonce, PeerIdentity signWith,
                                           PeerStatement? statement = null )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoEvictionDisallowed );
            w.WriteUInt64( nonce );
        }, signWith, statement );
    }

    /// <summary>
    /// The listener reports a protocol mismatch on either side.
    /// </summary>
    public static byte[] MissingProtocols( ulong nonce,
                                           IReadOnlyList<string> remoteMissing,
                                           IReadOnlyList<string> localMissing,
                                           PeerIdentity signWith,
                                           PeerStatement? statement = null )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoMissingProtocols );
            w.WriteUInt64( nonce );
            w.WriteSmallUInt32( (uint)remoteMissing.Count );
            foreach( var p in remoteMissing ) w.WriteString( p );
            w.WriteSmallUInt32( (uint)localMissing.Count );
            foreach( var p in localMissing ) w.WriteString( p );
        }, signWith, statement );
    }
    /// <summary>
    /// Writes a message body, then appends the identity block — the layout of the internal
    /// <c>ZeroProtocol.WriteIdentityBlockAndSign</c>: the tail of <paramref name="signWith"/>'s log,
    /// the pin statement, and one signature by its current key over everything before it.
    /// </summary>
    /// <param name="body">Writes the discriminator and the message-specific fields.</param>
    /// <param name="signWith">The identity presented and signing; null writes no identity block.</param>
    /// <param name="statement">What we state we pin for the receiver; null states nothing.</param>
    public static byte[] Build( BodyWriter body, PeerIdentity? signWith, PeerStatement? statement = null )
    {
        return signWith == null
                ? Build( body, null, null, null, null )
                : Build( body, signWith.Tail, signWith.Credential.Encoded, signWith.Credential.Key, statement );
    }

    /// <summary>
    /// The low-level form, for forgeries: any tail, signed by any key.
    /// </summary>
    /// <param name="body">Writes the discriminator and the message-specific fields.</param>
    /// <param name="tail">The events presented; null writes no identity block.</param>
    /// <param name="credential">The DER of the operational credential presented.</param>
    /// <param name="signer">The key that signs the transcript: normally the credential's.</param>
    /// <param name="statement">What we state we pin for the receiver; null states nothing.</param>
    public static byte[] Build( BodyWriter body, IReadOnlyList<KeyEvent>? tail, byte[]? credential, ECDsa? signer, PeerStatement? statement )
    {
        using var seq = new MutableSequence<byte>();
        var w = new FastByteWriter( seq );
        body( ref w );
        if( tail != null )
        {
            if( signer == null ) throw new ArgumentNullException( nameof( signer ) );
            if( credential == null ) throw new ArgumentNullException( nameof( credential ) );
            w.WriteSmallUInt32( 0 );                          // identity block serialization version
            w.WriteSmallUInt32( (uint)tail.Count );
            foreach( var e in tail )
            {
                w.WriteSmallUInt32( (uint)e.Encoded.Length );
                w.WriteBytes( e.Encoded.Span );
            }
            if( statement == null )
            {
                w.WriteSmallUInt32( 0 );
            }
            else
            {
                w.WriteSmallUInt32( (uint)statement.Seq + 1 );
                w.WriteBytes( statement.Digest );
            }
            w.WriteSmallUInt32( (uint)credential.Length );
            w.WriteBytes( credential );
            // Commit so the sequence holds every byte written so far: the signed hash covers
            // exactly this prefix and NOT the signature that follows.
            w.Commit();
            Span<byte> hash = stackalloc byte[64];
            ComputeSha512( seq, hash );
            var sig = signer.SignHash( hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
            w.WriteByte( (byte)sig.Length );
            w.WriteBytes( sig );
        }
        w.Commit();
        return seq.GetReadOnlySequence().ToArray();
    }

    static void ComputeSha512( MutableSequence<byte> seq, Span<byte> hash )
    {
        using var h = IncrementalHash.CreateHash( HashAlgorithmName.SHA512 );
        foreach( var s in seq.GetReadOnlySequence() ) h.AppendData( s.Span );
        h.GetCurrentHash( hash );
    }
}
