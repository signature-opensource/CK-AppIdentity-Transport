using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests.Adversarial;

/// <summary>
/// Builds Zero Protocol reply payloads for the adversarial peer.
/// <para>
/// Independent of the production writers (which are internal anyway), so the harness can emit
/// messages the production code would never emit: signed by the wrong key, echoing a stale nonce,
/// carrying an oversized field. Every builder takes its signing identities explicitly — that
/// parameter is the knob each C2 test turns.
/// </para>
/// </summary>
static class PeerMessages
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
                                         IReadOnlyList<PeerIdentity> signWith,
                                         PeerPublicKey? supposedIdentity = null,
                                         bool canAutoTrust = false )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteBytes( PeerInitialMessage.Prefix );
            w.WriteSmallUInt32( 0 );                      // ZeroProtocol.CurrentVersion
            w.WriteString( instanceId );
            w.WriteString( fullName );
            w.WriteSmallUInt32( (uint)availableProtocols.Count );
            foreach( var p in availableProtocols ) w.WriteString( p );
            w.WriteSmallInt32( expectedCommonProtocolCount );
            if( supposedIdentity != null )
            {
                w.WriteBool( true );
                w.WriteDateTime( supposedIdentity.TimeName );
                w.WriteSmallUInt32( (uint)supposedIdentity.SubjectPublicKeyInfo.Length );
                w.WriteBytes( supposedIdentity.SubjectPublicKeyInfo );
            }
            else
            {
                w.WriteBool( false );
            }
            w.WriteBool( canAutoTrust );
            // Per-connection key agreement material, inside the signed region.
            w.WriteSmallUInt32( (uint)ephemeralPublicKey.Length );
            w.WriteBytes( ephemeralPublicKey );
            w.WriteByte( macCapabilities );
            // The timed nonce.
            w.WriteDateTime( nonceCreationTime );
            w.WriteUInt64( nonce );
        }, signWith );
    }

    /// <summary>
    /// The listener's success reply: the negotiated protocol list, signed.
    /// </summary>
    /// <param name="nonce">Must echo the initiator's nonce.</param>
    /// <param name="initialClockOffset">The offset the peer computed from the initiator's nonce time.</param>
    /// <param name="now">The peer's current time (the initiator finishes the clock-offset calculation with it).</param>
    /// <param name="protocolFullNames">The accepted protocols, as "Name.Version".</param>
    /// <param name="signWith">Identities presented and signed with, most recent first.</param>
    public static byte[] AcceptedProtocols( ulong nonce,
                                            TimeSpan initialClockOffset,
                                            DateTime now,
                                            IReadOnlyList<string> protocolFullNames,
                                            byte[] ephemeralPublicKey,
                                            MacAlgorithm macAlgorithm,
                                            IReadOnlyList<PeerIdentity> signWith )
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
        }, signWith );
    }

    /// <summary>
    /// The usual success reply: echoes the initiator's nonce, accepts exactly the protocols it
    /// offered, and completes the key agreement with a fresh ephemeral and the strongest MAC both
    /// sides can run.
    /// </summary>
    /// <param name="initial">The initial message being answered.</param>
    /// <param name="now">Our current time.</param>
    /// <param name="signWith">Identities to present and sign with — the knob the C2 tests turn.</param>
    /// <param name="ephemeral">
    /// Our ephemeral key pair. A fresh one is created when null; a test passes an existing one to
    /// REUSE it across connections, which a real peer never does.
    /// </param>
    public static byte[] AcceptedProtocols( PeerInitialMessage initial,
                                            DateTime now,
                                            IReadOnlyList<PeerIdentity> signWith,
                                            PeerEphemeral? ephemeral = null )
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
                                      signWith );
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
                                    IReadOnlyList<PeerIdentity> signWith )
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
        }, signWith );
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
                                       IReadOnlyList<PeerIdentity>? signWith )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoRejectRemote );
            w.WriteUInt64( nonce );
            w.WriteByte( issue );
            w.WriteNullableTimeSpan( clockOffset );
            w.WriteString( enlistUrl ?? string.Empty );
            // The bool says whether an identity block follows.
            w.WriteBool( signWith != null );
        }, signWith );
    }

    /// <summary>
    /// The listener refuses to be evicted by this new connection.
    /// </summary>
    public static byte[] EvictionDisallowed( ulong nonce, IReadOnlyList<PeerIdentity> signWith )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoEvictionDisallowed );
            w.WriteUInt64( nonce );
        }, signWith );
    }

    /// <summary>
    /// The listener reports a protocol mismatch on either side.
    /// </summary>
    public static byte[] MissingProtocols( ulong nonce,
                                           IReadOnlyList<string> remoteMissing,
                                           IReadOnlyList<string> localMissing,
                                           IReadOnlyList<PeerIdentity> signWith )
    {
        return Build( ( ref FastByteWriter w ) =>
        {
            w.WriteByte( DNegoMissingProtocols );
            w.WriteUInt64( nonce );
            w.WriteSmallUInt32( (uint)remoteMissing.Count );
            foreach( var p in remoteMissing ) w.WriteString( p );
            w.WriteSmallUInt32( (uint)localMissing.Count );
            foreach( var p in localMissing ) w.WriteString( p );
        }, signWith );
    }

    /// <summary>
    /// Writes a message body, then appends the identity block and one signature per identity over
    /// the SHA-512 of everything written so far — the layout of the internal
    /// <c>ZeroProtocol.WriteIdentityKeysAndSign</c>.
    /// </summary>
    /// <param name="body">Writes the discriminator and the message-specific fields.</param>
    /// <param name="signWith">Identities to present and sign with; null writes no identity block.</param>
    public static byte[] Build( BodyWriter body, IReadOnlyList<PeerIdentity>? signWith )
    {
        using var seq = new MutableSequence<byte>();
        var w = new FastByteWriter( seq );
        body( ref w );
        if( signWith != null )
        {
            w.WriteSmallUInt32( 0 );                          // identity block serialization version
            w.WriteSmallUInt32( (uint)signWith.Count );
            foreach( var k in signWith )
            {
                w.WriteDateTime( k.TimeName );
                w.WriteSmallUInt32( (uint)k.SubjectPublicKeyInfo.Length );
                w.WriteBytes( k.SubjectPublicKeyInfo );
            }
            // Commit so the sequence holds every byte written so far: the signed hash covers
            // exactly this prefix and NOT the signatures that follow.
            w.Commit();
            Span<byte> hash = stackalloc byte[64];
            ComputeSha512( seq, hash );
            foreach( var k in signWith )
            {
                var sig = k.SignHash( hash );
                w.WriteByte( (byte)sig.Length );
                w.WriteBytes( sig );
            }
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
