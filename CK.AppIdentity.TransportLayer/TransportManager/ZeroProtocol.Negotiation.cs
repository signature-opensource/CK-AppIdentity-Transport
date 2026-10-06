using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

static partial class ZeroProtocol // Negotiation
{
    /// <summary>
    /// Maximum UTF-8 byte length of a resolved "EnlistRemoteUrl". It is a raw configuration value
    /// that travels inside negotiation messages, so it needs a bound and a budget term of its own -
    /// without them a long or non-ASCII URL pushes the reply past <see cref="FirstAnswerMaxLength"/>
    /// and the message is dropped as Invalid.
    /// </summary>
    public const int MaxEnlistRemoteUrlLength = 1024;

    public const int FirstAnswerMaxLength = 1 // One byte discriminator.
                                            + (5 + MaxEnlistRemoteUrlLength) // An authenticated RejectRemote carries the enlist URL.
                                            + 8 + 8 + 8 // Nonce, the offset it computed and its current time.
                                            + 5 // Number of common protocol (allows uint.MaxValue even if it's caped by MessageProtocolMap.MaxCount)
                                            + MessageProtocolMap.MaxCount * (2 * MessageProtocol.FullNameMaxLength)
                                            + (5 + RunPhaseProtection.MaxEphemeralPublicKeyLength) // The listener's ephemeral ECDH public key.
                                            + 1 // The MAC algorithm it selected.
                                            + (5 + Transport.CertificateBindingLength) // What it states about the certificate it presents.
                                            + 1 // Whether the identity block follows (RejectRemote).
                                            + IdentityBlockMaxLength;

    // Static messages use no initialization lock (we don't care of the rare case where 2 concurrent messages will be instantiated).
    // DNegoDowngradeProtocol followed by our CurrentVersion: it can be static.
    static IOutgoingMessage? _downgradeProtocolReplyMessage;
    // DNegoFinalFailureMessage: it can be static.
    static IOutgoingMessage? _finalFailureMessage;

    public enum ConfigurationOrTrustIssue : byte
    {
        Unknown = 0,
        DisallowedTransport = 1,
        InvalidClockOffset = 2,
        InitiatorConflict = 3,
        UnsupportedTransport = 4,
        ListenerRequiresLocalApproval = 5,
        ListenerRequiresRemoteApproval = 6,
        RequiresBothApproval = 7,

        /// <summary>
        /// The listener pins, for the initiator, a key event log the initiator's does not extend: a rollback
        /// (usually a message a rotation overtook) or a fork. The reply is signed and carries the listener's
        /// pin statement, so that an initiator whose identity was taken over learns it from the very refusal.
        /// </summary>
        IdentityConflict = 8,

        MaxValue = 8
    }


    public const int MaxEnlistUrlLength = 2048;

    /// <summary>
    /// Creates a <see cref="TimedNonce"/> and writes it.
    /// </summary>
    /// <param name="w">The writer.</param>
    /// <param name="clock">The system clock.</param>
    /// <returns>The generated nonce.</returns>
    static TimedNonce CreateAndWriteNonce( ref FastByteWriter w, ISystemClock clock )
    {
        var timedNonce = TimedNonce.Create( clock );
        w.WriteDateTime( timedNonce.CreationTime );
        w.WriteUInt64( timedNonce.Nonce );
        return timedNonce;
    }

    /// <summary>
    /// Reads a <see cref="TimedNonce"/> (written by <see cref="CreateAndWriteNonce(ref FastByteWriter, ISystemClock)"/>).
    /// The message signature must first be verified and then the nonce must be checked if signature verification succeeded,
    /// otherwise it would be easy to flood invalid messages that would flush the nonce cache.
    /// </summary>
    /// <param name="r">The reader.</param>
    /// <returns>The nonce.</returns>
    static TimedNonce ReadNonce( ref FastByteReader r ) => new TimedNonce( r.ReadDateTime(), r.ReadUInt64() );

    /// <summary>
    /// Writes what this side states about the certificate it is presenting: length then bytes, a
    /// length of 0 meaning that this transport presents none. One byte on a cleartext transport.
    /// <para>
    /// This must be written before <see cref="WriteIdentityBlockAndSign"/>, which hashes everything
    /// already in the sequence: the statement is worth nothing unless it is signed.
    /// </para>
    /// </summary>
    static void WriteCertificateBinding( ref FastByteWriter w, ReadOnlyMemory<byte> binding )
    {
        w.WriteSmallUInt32( (uint)binding.Length );
        if( binding.Length > 0 ) w.WriteBytes( binding.Span );
    }

    /// <summary>
    /// Reads what the peer states about the certificate it is presenting. The result is checked by
    /// <see cref="CheckCertificateBinding"/> once the message's signature has been verified — an
    /// unsigned statement about a certificate says nothing about who made it, and reporting a relay
    /// on the strength of one would name an attack every time a scanner sends noise.
    /// </summary>
    public static byte[]? ReadCertificateBinding( ref FastByteReader r )
    {
        uint len = r.ReadSmallUInt32();
        Throw.CheckData( len == 0 || len == Transport.CertificateBindingLength );
        return len == 0 ? null : r.ReadBytes( len );
    }

    /// <summary>
    /// Checks the peer's statement against the certificate the transport actually received.
    /// <para>
    /// The two must say the same thing. Anything that terminates the channel between the peers has to
    /// present a certificate of its own, so a relay shows up here as a statement that does not match
    /// what arrived. The two asymmetric cases are just as wrong and are worth their own message: they
    /// are a transport mismatch, one side believing it is secured while the other is not.
    /// </para>
    /// </summary>
    public static void CheckCertificateBinding( byte[]? attested, Transport transport )
    {
        var actual = transport.RemoteCertificateBinding;
        if( attested == null )
        {
            Throw.CheckData( "The peer presented a certificate but stated none.", actual.IsEmpty );
        }
        else
        {
            Throw.CheckData( "The peer stated a certificate on a connection that presented none.", !actual.IsEmpty );
            Throw.CheckData( "The peer stated a certificate that is not the one it presented.",
                             attested.AsSpan().SequenceEqual( actual.Span ) );
        }
    }

    /// <summary>
    /// Upper bound of an identity block: the events, the pin statement and one signature.
    /// </summary>
    public const int IdentityBlockMaxLength = 5 // Version.
                                              + 5 // Event count.
                                              + KeyEventChain.MaxEventTail * (5 + KeyEvent.MaxEncodedSize)
                                              + 5 + KeyEvent.HashSize // The pin statement.
                                              + 1 + 255; // The signature, byte-length prefixed.

    /// <summary>
    /// Writes the identity block and signs everything written so far with the current identity key.
    /// <list type="bullet">
    ///   <item>The tail of the sender's key event log: it proves which key is current, and lets a
    ///   receiver that pinned an earlier event catch up through rotations the sender committed to.</item>
    ///   <item>The pin statement: what the sender pins for the receiver (sequence and event digest), so
    ///   that a party can learn that someone rotated or forked its identity elsewhere.</item>
    ///   <item>One signature, by the key the head of the tail reveals, over everything before it.</item>
    /// </list>
    /// The tail and the key come from one snapshot (<see cref="ILocalKeys.State"/>): read separately,
    /// a rotation in between would pair a tail with a key of another rotation.
    /// </summary>
    /// <param name="w">The writer.</param>
    /// <param name="localKeys">The sender's keys.</param>
    /// <param name="receiver">The sender's view of the receiver, for the pin statement. Null when the receiver is not known.</param>
    static void WriteIdentityBlockAndSign( ref FastByteWriter w, ILocalKeys localKeys, IRemoteKeys? receiver )
    {
        var state = localKeys.State;
        // Independent serialization version for the identity block.
        w.WriteSmallUInt32( 0 );
        var tail = state.Tail;
        w.WriteSmallUInt32( (uint)tail.Count );
        foreach( var e in tail )
        {
            w.WriteSmallUInt32( (uint)e.Encoded.Length );
            w.WriteBytes( e.Encoded.Span );
        }
        var pinned = receiver?.TrustedEvent;
        if( pinned == null )
        {
            w.WriteSmallUInt32( 0 );
        }
        else
        {
            w.WriteSmallUInt32( (uint)pinned.Seq + 1 );
            w.WriteBytes( pinned.GetDigest( receiver!.Party.FullName ).Span );
        }
        ComputeSHA512HashAndAppendSignature( ref w, state.Key );
    }

    /// <summary>
    /// Reads the identity block written by <see cref="WriteIdentityBlockAndSign"/>, applies the tail
    /// to what we pin for the sender, and verifies the signature with the key at its head.
    /// <para>
    /// The tail is applied before the signature is checked, on purpose: an event proves itself, so a
    /// verified rotation (or abandonment) is kept whatever happens to this message. What the tail does
    /// not prove is that the sender holds the head's key: that is the signature, and it decides
    /// <see cref="SignatureCheck.Trusted"/> versus <see cref="SignatureCheck.SelfAsserted"/>.
    /// </para>
    /// </summary>
    /// <param name="r">The reader.</param>
    /// <param name="logger">The logger to use.</param>
    /// <param name="senderFullName">The full name the sender claims: the events are verified for it.</param>
    /// <param name="senderKeys">What we know of the sender, or null when it is not one of our remotes.</param>
    /// <param name="block">Outputs what was read.</param>
    /// <returns>
    /// Whether the signature verifies AND against what. See <see cref="SignatureCheck"/>:
    /// <see cref="SignatureCheck.SelfAsserted"/> is not an authentication.
    /// </returns>
    public static SignatureCheck ReadIdentityBlockAndVerify( ref FastByteReader r,
                                                             IActivityLineEmitter logger,
                                                             string senderFullName,
                                                             IRemoteKeys? senderKeys,
                                                             out IdentityBlock block )
    {
        Throw.CheckData( r.ReadSmallUInt32() == 0 ); // Version.
        var count = r.ReadSmallUInt32();
        Throw.CheckData( count >= 1 && count <= KeyEventChain.MaxEventTail );
        var tail = new KeyEvent[count];
        for( int i = 0; i < tail.Length; ++i )
        {
            var len = r.ReadSmallUInt32();
            Throw.CheckData( len > 0 && len <= KeyEvent.MaxEncodedSize );
            tail[i] = KeyEvent.Read( r.ReadBytes( len ) );
        }
        int? statedSeq = null;
        byte[]? statedDigest = null;
        var stated = r.ReadSmallUInt32();
        if( stated != 0 )
        {
            Throw.CheckData( stated <= int.MaxValue );
            statedSeq = (int)(stated - 1);
            statedDigest = r.ReadBytes( KeyEvent.HashSize );
        }
        Span<byte> hash = stackalloc byte[64];
        ComputeHash( r.GetBeforeHead(), hash );
        var lenSignature = r.ReadByte();
        Span<byte> signature = stackalloc byte[lenSignature];
        r.ReadBytes( signature );

        var chain = senderKeys != null
                        ? senderKeys.ApplyTail( logger, tail )
                        : KeyEventChain.Verify( senderFullName, tail, null );
        var head = tail[^1];
        // Malformed bytes in the head are the peer's fault: InvalidDataException, like any other.
        var headKeyData = new RemoteIdentityKeyData( head );
        SignatureCheck check;
        RemoteIdentityKey? headKey = null;
        switch( chain.Verdict )
        {
            case KeyChainVerdict.UpToDate:
            case KeyChainVerdict.Advanced:
                // The pin is now the head: reuse its key rather than build one per handshake. Another
                // connection may have moved the pin further meanwhile, hence the check.
                var pinnedKey = senderKeys!.TrustedIdentity;
                headKey = pinnedKey != null && pinnedKey.Equals( headKeyData ) ? pinnedKey : new RemoteIdentityKey( headKeyData );
                check = headKey.VerifyHash( hash, signature ) ? SignatureCheck.Trusted : SignatureCheck.Failed;
                break;
            case KeyChainVerdict.Unpinned:
            case KeyChainVerdict.TooFarBehind:
                // Verifying against the key the sender just supplied proves only that it holds some key.
                headKey = new RemoteIdentityKey( headKeyData );
                check = headKey.VerifyHash( hash, signature ) ? SignatureCheck.SelfAsserted : SignatureCheck.Failed;
                break;
            default:
                // Invalid, Rollback, Duplicity, Abandoned, Terminated: nothing to accept. What could be
                // applied (an abandonment, duplicity evidence) has been by ApplyTail.
                check = SignatureCheck.Failed;
                break;
        }
        block = new IdentityBlock( chain.Verdict, head, headKeyData, headKey, statedSeq, statedDigest );
        return check;
    }


    /// <summary>
    /// Computes the SHA512 of the <see cref="FastByteWriter.GetBeforeHead()"/> and writes its signature with the <paramref name="identityKey"/>.
    /// </summary>
    /// <param name="w">The writer.</param>
    /// <param name="identityKey">The signer to use.</param>
    static void ComputeSHA512HashAndAppendSignature( ref FastByteWriter w, LocalIdentityKey identityKey )
    {
        Span<byte> messageHash = stackalloc byte[64];
        Span<byte> signature = stackalloc byte[256];
        ComputeHash( w.GetBeforeHead(), messageHash );
        Throw.CheckData( identityKey.TrySignHash( messageHash, signature, out int byteWritten ) );
        // See above: the length is written on one byte and 256 would encode as 0.
        Throw.CheckData( "Signature length must fit on one byte.", byteWritten <= 255 );
        w.WriteByte( (byte)byteWritten );
        w.WriteBytes( signature.Slice( 0, byteWritten ) );
        w.Commit();
    }

    /// <summary>
    /// Computes the SHA512 of the <see cref="FastByteReader.GetBeforeHead()"/>, reads its signature from <see cref="r"/>
    /// and verify it against <paramref name="key"/>.
    /// </summary>
    /// <param name="r">The reader.</param>
    /// <param name="key">The verifier to use.</param>
    /// <returns>True if the signature can be verified.</returns>
    static bool ComputeSHA512HashAndVerifySignature( ref FastByteReader r, RemoteIdentityKey key )
    {
        Span<byte> messageHash = stackalloc byte[64];
        ComputeHash( r.GetBeforeHead(), messageHash );
        var lenSignature = r.ReadByte();
        Span<byte> signature = stackalloc byte[lenSignature];
        r.ReadBytes( signature );
        return key.VerifyHash( messageHash, signature );
    }

    static void ComputeHash( ReadOnlySequence<byte> message, Span<byte> hash )
    {
        using var h = IncrementalHash.CreateHash( HashAlgorithmName.SHA512 );
        foreach( var s in message )
        {
            h.AppendData( s.Span );
        }
        h.GetCurrentHash( hash );
    }

    /// <summary>
    /// Tries to send a TransportMessage of the <see cref="TransportFeature.OutgoingInitialMessage"/> in a specific version
    /// and returns a random nonce on success.
    /// </summary>
    /// <param name="systemClock">The system clock to use.</param>
    /// <param name="transport">The newly created transport.</param>
    /// <param name="initialMessage">The <see cref="TransportFeature.OutgoingInitialMessage"/>.</param>
    /// <param name="version">The serialization version.</param>
    /// <returns>A nonce or null if <see cref="Transport.IsCondemned"/> has been signaled or if the <paramref name="version"/> is not locally supported.</returns>
    public static async ValueTask<ulong?> SendInitialMessageAsync( ISystemClock systemClock,
                                                                   Transport transport,
                                                                   InitialMessage initialMessage,
                                                                   int version,
                                                                   byte macCapabilities )
    {
        // The ephemeral key belongs to THIS connection: it is created on the Transport, never on
        // the TransportFeature, whose OutgoingInitialMessage is cached and reused across attempts.
        // Writing it here rather than inside InitialMessage keeps that cached content untouched.
        var ephemeralPublicKey = transport.CreateEphemeralPublicKey();
        Throw.DebugAssert( "We are the initiator: the transport knows its remote.", transport.RemoteKeys != null );
        using var m = CreateAndSignMessage( systemClock, initialMessage, version, ephemeralPublicKey,
                                            macCapabilities, transport.LocalCertificateBinding, transport.RemoteKeys, out var nonce );
        if( !await transport.SendAsync( 0, m ).ConfigureAwait( false ) ) return null;
        return nonce;

        static IOutgoingMessage CreateAndSignMessage( ISystemClock systemClock,
                                                      InitialMessage initialMessage,
                                                      int version,
                                                      byte[] ephemeralPublicKey,
                                                      byte macCapabilities,
                                                      ReadOnlyMemory<byte> certificateBinding,
                                                      IRemoteKeys remoteKeys,
                                                      out ulong nonce )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );

            // There is currently only one version.
            Throw.CheckArgument( version == CurrentVersion );
            // Writes the message content (current version).
            initialMessage.WriteCurrentVersion( ref w );

            // Per-connection key agreement material, inside the signed region.
            w.WriteSmallUInt32( (uint)ephemeralPublicKey.Length );
            w.WriteBytes( ephemeralPublicKey );
            // The byte comes from the caller, captured ONCE per connection. CapabilityRestriction is a
            // mutable process-wide static, so reading it again at derivation time could put a
            // different value in the transcript than the one actually sent, and the two sides would
            // derive different keys.
            w.WriteByte( macCapabilities );

            // What this side is presenting on the channel underneath, inside the signed region.
            WriteCertificateBinding( ref w, certificateBinding );

            // Writes the nonce (creation time and 64 bits nonce) ang gets its value:
            // the creation time will be used to compute the clock offset and the nonce value will
            // be reused for the subsequent messages during this negotiation.
            nonce = CreateAndWriteNonce( ref w, systemClock ).Nonce;
            // Writes the identity keys and sign the message with them.
            WriteIdentityBlockAndSign( ref w, remoteKeys.LocalKeys, remoteKeys );
            return builder.CreateMessage( sequence );
        }
    }

    static bool CheckExpectedNonce( IParallelLogger logger, ref FastByteReader r, TransportFeature remote, ulong expectedNonce )
    {
        if( expectedNonce != r.ReadUInt64() )
        {
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"The remote '{remote.RemoteKeys.Party}' sent an invalid Nonce." );
            return false;
        }
        return true;
    }

    public static async ValueTask<bool> SendRejectRemoteReplyMessageAsync( Transport transport,
                                                                           IRemoteKeys? remoteKeys,
                                                                           ConfigurationOrTrustIssue protocolIssue,
                                                                           TimeSpan? clockOffset,
                                                                           string? enlistUrl,
                                                                           ulong nonce )
    {
        using var m = CreateMessage( remoteKeys, protocolIssue, clockOffset, enlistUrl, nonce );
        return await transport.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateMessage( IRemoteKeys? remoteKeys,
                                               ConfigurationOrTrustIssue protocolIssue,
                                               TimeSpan? clockOffset,
                                               string? enlistUrl,
                                               ulong nonce )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );
            w.WriteByte( DNegoRejectRemote );
            w.WriteUInt64( nonce );
            w.WriteByte( (byte)protocolIssue );
            w.WriteNullableTimeSpan( clockOffset );
            // To be able to use the ReadString( maxLength ).
            w.WriteString( enlistUrl ?? string.Empty );
            // When the incoming remote is not known at all, we don't have local
            // keys (we cannot locate the local party to use so we take no risk: selecting the root
            // ApplicationIdentityService local is not a good idea).
            if( remoteKeys == null )
            {
                w.WriteBool( false );
                w.Commit();
            }
            else
            {
                w.WriteBool( true );
                WriteIdentityBlockAndSign( ref w, remoteKeys.LocalKeys, remoteKeys );
            }
            return builder.CreateMessage( sequence );
        }
    }

    public static void ReadRejectRemoteReplyMessage( IActivityLineEmitter logger,
                                                     IncomingMessage message,
                                                     ulong expectedNonce,
                                                     IRemoteKeys remoteKeys,
                                                     out bool nonceFailure,
                                                     out ConfigurationOrTrustIssue issue,
                                                     out TimeSpan? clockOffset,
                                                     out string? enlistUrl,
                                                     out IdentityBlock? block,
                                                     out SignatureCheck signatureCheck )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoRejectRemote );

        nonceFailure = expectedNonce != r.ReadUInt64();
        issue = (ConfigurationOrTrustIssue)r.ReadByte();
        clockOffset = r.ReadNullableTimeSpan();
        Throw.CheckData( issue <= ConfigurationOrTrustIssue.MaxValue );
        enlistUrl = r.ReadString( MaxEnlistUrlLength );
        if( enlistUrl.Length == 0 ) enlistUrl = null;
        // Do we have the identity keys and the signatures?
        if( r.ReadBool() )
        {
            signatureCheck = ReadIdentityBlockAndVerify( ref r, logger, remoteKeys.Party.FullName, remoteKeys, out var read );
            block = read;
        }
        else
        {
            signatureCheck = SignatureCheck.Failed;
            block = null;
        }
    }


    public static async ValueTask<bool> SendRequiredEnlistUrlMessageAsync( Transport transport, string? enlistUrl, ulong nonce )
    {
        Throw.DebugAssert( "We are on the initiator side.", transport.RemoteKeys != null );

        using var m = CreateMessage( transport, enlistUrl, nonce );
        return await transport.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateMessage( Transport transport, string? enlistUrl, ulong nonce )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );
            w.WriteByte( DNegoRequiredEnlistUrl );
            w.WriteUInt64( nonce );
            // To be able to use the ReadString( maxLength ).
            w.WriteString( enlistUrl ?? string.Empty );
            ComputeSHA512HashAndAppendSignature( ref w, transport.RemoteKeys!.LocalKeys.CurrentIdentity );
            return builder.CreateMessage( sequence );
        }
    }

    public static bool ReadRequiredEnlistUrlMessage( IncomingMessage message,
                                                     ulong expectedNonce,
                                                     RemoteIdentityKey remoteIdentity,
                                                     out string? enlistUrl )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoRequiredEnlistUrl );
        if( expectedNonce != r.ReadUInt64() )
        {
            enlistUrl = null;
            return false;
        }
        enlistUrl = r.ReadString( MaxEnlistUrlLength );
        if( enlistUrl.Length == 0 ) enlistUrl = null;
        return ComputeSHA512HashAndVerifySignature( ref r, remoteIdentity );
    }

    /// <summary>
    /// Off remote reply message is a signed message with the local identities.
    /// </summary>
    /// <param name="transport">The transport.</param>
    /// <param name="nonce">The expected nonce.</param>
    /// <param name="expectedAvailableTime">The expected back online time.</param>
    /// <returns>True if the message has been sent, false if Transport has been canceled.</returns>
    public static async ValueTask<bool> SendOffRemoteMessageAsync( Transport transport, ulong nonce, TimeSpan clockOffset, GoodbyeMessage offMessage )
    {
        Throw.DebugAssert( transport.RemoteKeys != null );
        using var m = CreateAndSignMessage( nonce, clockOffset, offMessage, transport.RemoteKeys );
        return await transport.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateAndSignMessage( ulong nonce, TimeSpan clockOffset, GoodbyeMessage offMessage, IRemoteKeys keys )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );
            w.WriteByte( DNegoOffRemote );
            w.WriteUInt64( nonce );
            w.WriteTimeSpan( clockOffset );
            // Avoids a recurring reason to stop.
            if( offMessage.IsFromRemote )
            {
                w.WriteBool( false );
            }
            else
            {
                w.WriteBool( true );
                GoodbyeMessage.WriteMessage( ref w, offMessage );
            }
            WriteIdentityBlockAndSign( ref w, keys.LocalKeys, keys );
            return builder.CreateMessage( sequence );
        }
    }

    public static bool ReadOffRemoteMessage( IParallelLogger logger,
                                             TransportFeature remote,
                                             IncomingMessage message,
                                             ulong expectedNonce,
                                             out TimeSpan clockOffset,
                                             out GoodbyeMessage? offMessage )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoOffRemote );

        offMessage = null;
        if( !CheckExpectedNonce( logger, ref r, remote, expectedNonce ) )
        {
            clockOffset = default;
            return false;
        }
        clockOffset = r.ReadTimeSpan();
        if( r.ReadBool() )
        {
            offMessage = GoodbyeMessage.ReadMessage( ref r );
        }
        var check = ReadIdentityBlockAndVerify( ref r, logger, remote.Party.FullName, remote.RemoteKeys, out var block );
        // Switching a remote off on the strength of a self-asserted signature would let anyone
        // answering on this connection take it down with a single packet and no key material.
        if( !remote.RemoteKeys.IsTrustedAfterRead( logger, check, block ) )
        {
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                          $"Received {(check == SignatureCheck.Failed ? "unverifiable" : "untrusted (self-asserted)")} " +
                          $"Remote Off message from '{remote.RemoteKeys.Party}'." );
            return false;
        }
        logger.Info( $"Received verified Remote Off message from '{remote.RemoteKeys.Party}': {offMessage}." );
        return true;
    }

    public static ValueTask<bool> SendDowngradeProtocolReplyAsync( Transport transport )
    {
        _downgradeProtocolReplyMessage ??= _zeroFactory.CreateStatic( bytes =>
        {
            var w = new FastByteWriter( bytes );
            w.WriteByte( DNegoDowngradeProtocol );
            w.WriteSmallUInt32( CurrentVersion );
            w.Commit();
        } );
        return transport.SendAsync( 0, _downgradeProtocolReplyMessage );
    }

    /// <summary>
    /// Reads the version a listener asks us to fall back to.
    /// <para>
    /// A downgrade can only name a version below <see cref="CurrentVersion"/>: that is what "downgrade"
    /// means, and a version we cannot produce is not a negotiation, it is an invalid payload. Checking
    /// it here puts it on the path every other malformed message takes, instead of letting it reach
    /// <c>SendInitialMessageAsync</c> and fail an argument check from inside the connect task — which
    /// surfaces as an unhandled error about our own code rather than as what it is, a peer sending
    /// something it must not.
    /// </para>
    /// <para>
    /// With a single version defined, no value can satisfy this and every downgrade message is
    /// invalid. That is correct, not a placeholder: there is nothing below version 0 to fall back to.
    /// </para>
    /// </summary>
    public static int ReadDowngradeProtocolReplyMessage( IncomingMessage message )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoDowngradeProtocol );
        var version = r.ReadSmallUInt32();
        Throw.CheckData( version < CurrentVersion );
        return (int)version;
    }

    public static async ValueTask<bool> SendAcceptedProtocolsMessageAsync( ISystemClock systemClock,
                                                                           Transport transport,
                                                                           MessageProtocolMap protocolMap,
                                                                           ulong nonce,
                                                                           TimeSpan initialClockOffset,
                                                                           byte[] ephemeralPublicKey,
                                                                           MacAlgorithm macAlgorithm,
                                                                           byte macCapabilities )
    {
        Throw.DebugAssert( transport.RemoteKeys != null );
        using var m = CreateAndSignMessage( systemClock, protocolMap, nonce, initialClockOffset,
                                            ephemeralPublicKey, macAlgorithm, macCapabilities,
                                            transport.LocalCertificateBinding,
                                            transport.RemoteKeys );
        return await transport.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateAndSignMessage( ISystemClock systemClock,
                                                      in MessageProtocolMap protocolMap,
                                                      ulong nonce,
                                                      TimeSpan initialClockOffset,
                                                      byte[] ephemeralPublicKey,
                                                      MacAlgorithm macAlgorithm,
                                                      byte macCapabilities,
                                                      ReadOnlyMemory<byte> certificateBinding,
                                                      IRemoteKeys keys )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );

            w.WriteByte( DNegoAcceptedProtocolsMessage );
            w.WriteUInt64( nonce );
            w.WriteTimeSpan( initialClockOffset );
            w.WriteDateTime( systemClock.UtcNow );
            w.WriteSmallUInt32( (uint)protocolMap.Protocols.Count );
            foreach( var p in protocolMap.Protocols )
            {
                w.WriteString( p.FullName );
            }
            // The listener's half of the key agreement plus its selection, inside the signed region.
            w.WriteSmallUInt32( (uint)ephemeralPublicKey.Length );
            w.WriteBytes( ephemeralPublicKey );
            w.WriteByte( (byte)macAlgorithm );
            // The listener's own capabilities, inside the signed region and bound into the transcript.
            // Without this the initiator can check that the selection is one it offered, but not that
            // the listener could not have done better.
            w.WriteByte( macCapabilities );
            // What this side is presenting on the channel underneath, inside the signed region.
            WriteCertificateBinding( ref w, certificateBinding );
            WriteIdentityBlockAndSign( ref w, keys.LocalKeys, keys );
            return builder.CreateMessage( sequence );
        }
    }

    public static MessageProtocolMap TryReadAcceptedProtocolsMessage( TransportManager transportManager,
                                                                      Transport transport,
                                                                      IncomingMessage message,
                                                                      TransportFeature remote,
                                                                      ulong expectedNonce,
                                                                      out bool foundTrustedKey,
                                                                      out TimeSpan currentClockOffset,
                                                                      out byte[]? ephemeralPublicKey,
                                                                      out MacAlgorithm macAlgorithm,
                                                                      out byte macCapabilities )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoAcceptedProtocolsMessage );
        foundTrustedKey = false;
        ephemeralPublicKey = null;
        macAlgorithm = MacAlgorithm.Invalid;
        macCapabilities = 0;
        if( !CheckExpectedNonce( transportManager.Logger, ref r, remote, expectedNonce ) )
        {
            currentClockOffset = TimeSpan.Zero;
            return default;
        }
        var otherClockDrift = r.ReadTimeSpan();
        currentClockOffset = ((transportManager.SystemClock.UtcNow - r.ReadDateTime()) - otherClockDrift) / 2;
        uint count = r.ReadSmallUInt32();
        if( count > MessageProtocolMap.MaxCount )
        {
            transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' returned {count} protocols, MessageProtocolMap.MaxCount is {MessageProtocolMap.MaxCount}." );
            return default;
        }
        // A valid answer is composed only of different protocol names (a single version per protocol) and
        // all our BestRegisteredProtocols must be satisfied (may be with an old version).
        var protocols = new MessageProtocol[count];
        for( int i = 0; i < count; ++i )
        {
            var fullName = r.ReadString( MessageProtocol.FullNameMaxLength );
            var p = remote.RegisteredProtocols.FirstOrDefault( p => p.FullName.Equals( fullName, StringComparison.OrdinalIgnoreCase ) );
            if( p == null )
            {
                transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' returned an unwanted protocol '{fullName}'." );
                return default;
            }
            protocols[i] = p;
        }
        // The names come from the peer, so duplicates and wrong ordering are malformed input.
        // InternalGet states them with Throw.CheckArgument (ArgumentException), which ConnectionFault
        // does not classify as a peer fault - and this runs BEFORE the signature check below, so an
        // unauthenticated peer could raise a full-stack Error with ToBeInvestigated per connection.
        Throw.CheckData( "Protocol names must be unique and sorted.",
                         protocols.Select( p => p.Name ).IsSortedStrict() );
        var map = MessageProtocolMap.InternalGet( protocols );
        // The listener's half of the key agreement and the algorithm it selected.
        uint lenEphemeral = r.ReadSmallUInt32();
        Throw.CheckData( lenEphemeral > 0 && lenEphemeral <= RunPhaseProtection.MaxEphemeralPublicKeyLength );
        ephemeralPublicKey = r.ReadBytes( lenEphemeral );
        macAlgorithm = (MacAlgorithm)r.ReadByte();
        // Validate the enum here rather than trusting the byte. Downstream the value is used as
        // "1 << (int)macAlgorithm": C# masks a shift count to 5 bits, so 33 would alias onto the
        // AesGmac bit, pass the "did we offer it?" test, survive Derive's "not Invalid" guard and
        // fall through to the HMAC path - an undefined value becoming a live KDF parameter.
        Throw.CheckData( "Unknown MAC algorithm.",
                         macAlgorithm is MacAlgorithm.AesGmac or MacAlgorithm.HmacSha256 );
        macCapabilities = r.ReadByte();
        // Read now because it sits inside the signed region; checked below, once the signature says
        // whose statement this is.
        var attestedBinding = ReadCertificateBinding( ref r );
        var check = ReadIdentityBlockAndVerify( ref r, transportManager.Logger, remote.Party.FullName, remote.RemoteKeys, out var block );
        if( check == SignatureCheck.Failed )
        {
            transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                           $"Received unverifiable AcceptedProtocolsMessage message from '{remote.Party}'." );
            return default;
        }
        // The statement is signed by whoever sent it, so it can now be held against what arrived.
        // This runs BEFORE IsTrustedAfterRead because that call is not a query: under AutoTrustKey it
        // adopts the key it has just read and persists it as the .public file in the shared store.
        // Writing durable trust off a message we are about to reject as invalid is the wrong shape for
        // a security write, whoever it happens to benefit. The listener already does it in this order
        // (IncomingConnectionBackTask) and the two sides must agree on when trust may be persisted.
        CheckCertificateBinding( attestedBinding, transport );
        foundTrustedKey = remote.RemoteKeys.IsTrustedAfterRead( transportManager.Logger, check, block );
        if( !foundTrustedKey )
        {
            transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                                           $"Received untrusted (self-asserted) AcceptedProtocolsMessage message from '{remote.Party}'." );
            return default;
        }
        transportManager.Logger.Info( $"Received verified AcceptedProtocolsMessage message from '{remote.Party}'." );
        var missingProtocols = remote.BestRegisteredProtocols.Where( b => !protocols.Any( p => p.Name == b.Name ) );
        if( missingProtocols.Any() )
        {
            transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' cannot support protocols: '{missingProtocols.Select( p => p.FullName ).Concatenate( "' ,'" )}'." );
            return default;
        }
        return map;

    }

    /// <summary>
    /// Message sent by the <see cref="IncomingConnectionBackTask"/> when the transport is valid
    /// but <see cref="TransportFeature.DisallowEviction"/> is false.
    /// </summary>
    /// <param name="incoming">The transport.</param>
    /// <returns>True on success, false if transport has been canceled.</returns>
    public static async ValueTask<bool> SendEvictionDisallowedMessageAsync( Transport incoming, ulong nonce )
    {
        Throw.DebugAssert( incoming.RemoteKeys != null );
        using var m = CreateAndSignMessage( nonce, incoming.RemoteKeys );
        return await incoming.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateAndSignMessage( ulong nonce, IRemoteKeys keys )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );

            w.WriteByte( DNegoEvictionDisallowed );
            w.WriteUInt64( nonce );
            WriteIdentityBlockAndSign( ref w, keys.LocalKeys, keys );
            return builder.CreateMessage( sequence );
        }
    }

    public static bool ReadEvictionDisallowedMessage( IParallelLogger logger,
                                                      TransportFeature remote,
                                                      IncomingMessage message,
                                                      ulong expectedNonce )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoEvictionDisallowed );
        if( !CheckExpectedNonce( logger, ref r, remote, expectedNonce ) )
        {
            return false;
        }
        var check = ReadIdentityBlockAndVerify( ref r, logger, remote.Party.FullName, remote.RemoteKeys, out var block );
        if( !remote.RemoteKeys.IsTrustedAfterRead( logger, check, block ) )
        {
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                          $"Received {(check == SignatureCheck.Failed ? "unverifiable" : "untrusted (self-asserted)")} " +
                          $"Eviction Disallowed message from '{remote.RemoteKeys.Party}'." );
            return false;
        }
        logger.Info( $"Received verified Eviction Disallowed message from '{remote.RemoteKeys.Party}'." );
        return true;
    }

    /// <summary>
    /// Message sent by the <see cref="IncomingConnectionBackTask"/> when the initial message of the remote misses some
    /// of our protocols.
    /// </summary>
    /// <param name="incoming">The transport.</param>
    /// <param name="weAreMissing">The missing protocols on our listener side.</param>
    /// <param name="heIsMissing">The missing protocols on the caller side.</param>
    /// <returns>True on success, false if transport has been canceled.</returns>
    public static async ValueTask<bool> SendMissingProtocolsMessageAsync( Transport incoming,
                                                                          ulong nonce,
                                                                          List<string>? weAreMissing,
                                                                          List<string>? heIsMissing )
    {
        Throw.DebugAssert( incoming.RemoteKeys != null );
        using var m = CreateAndSignMessage( nonce, weAreMissing, heIsMissing, incoming.RemoteKeys );
        return await incoming.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateAndSignMessage( ulong nonce, List<string>? weAreMissing, List<string>? heIsMissing, IRemoteKeys keys )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );

            w.WriteByte( DNegoMissingProtocols );
            w.WriteUInt64( nonce );
            WriteMissing( ref w, weAreMissing );
            WriteMissing( ref w, heIsMissing );

            WriteIdentityBlockAndSign( ref w, keys.LocalKeys, keys );
            return builder.CreateMessage( sequence );

            static void WriteMissing( ref FastByteWriter w, List<string>? missing )
            {
                // Truncate to what the reader accepts. ReadProtocols refuses more than
                // MessageProtocolMap.MaxCount, so writing more does not merely lose the extra names -
                // the whole message is dropped and BOTH operators lose the diagnostic. A partial list
                // is worth strictly more than none.
                uint ourCount = missing != null ? (uint)Math.Min( missing.Count, MessageProtocolMap.MaxCount ) : 0;
                w.WriteSmallUInt32( ourCount );
                if( ourCount != 0 )
                {
                    Throw.DebugAssert( missing != null );
                    for( int i = 0; i < ourCount; ++i )
                    {
                        w.WriteString( missing[i] );
                    }
                }
            }
        }
    }

    public static bool TryReadMissingProtocolsMessage( IParallelLogger logger,
                                                       IncomingMessage message,
                                                       ulong expectedNonce,
                                                       TransportFeature remote,
                                                       out string[]? localMissing,
                                                       out string[]? remoteMissing )
    {
        localMissing = null;
        remoteMissing = null;
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoMissingProtocols );
        if( !CheckExpectedNonce( logger, ref r, remote, expectedNonce ) )
        {
            return false;
        }
        if( !ReadProtocols( ref r, remote, logger, out remoteMissing )
            || !ReadProtocols( ref r, remote, logger, out localMissing ) )
        {
            return false;
        }
        var check = ReadIdentityBlockAndVerify( ref r, logger, remote.Party.FullName, remote.RemoteKeys, out var block );
        if( !remote.RemoteKeys.IsTrustedAfterRead( logger, check, block ) )
        {
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                          $"Received {(check == SignatureCheck.Failed ? "unverifiable" : "untrusted (self-asserted)")} " +
                          $"MissingProtocols message from '{remote.Party}'." );
            return false;
        }
        logger.Info( $"Received verified MissingProtocols message from '{remote.Party}'." );
        return true;

        static bool ReadProtocols( ref FastByteReader r, TransportFeature remote, IParallelLogger logger, out string[]? protocols )
        {
            uint count = r.ReadSmallUInt32();
            if( count > MessageProtocolMap.MaxCount )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' returned {count} missing protocols, MessageProtocolMap.MaxCount is {MessageProtocolMap.MaxCount}." );
                protocols = null;
                return false;
            }
            protocols = new string[count];
            for( int i = 0; i < count; ++i )
            {
                protocols[i] = r.ReadString( MessageProtocol.FullNameMaxLength );
            }
            return true;
        }
    }

    public static ValueTask<bool> SendFinalFailureMessageAsync( Transport transport )
    {
        IOutgoingMessage m = _finalFailureMessage ??= _zeroFactory.CreateStatic( bytes =>
                                                            {
                                                                var m = bytes.GetSpan( 1 );
                                                                m[0] = DNegoFinalFailureMessage;
                                                                bytes.Advance( 1 );
                                                            } );
        return transport.SendAsync( 0, m );
    }

    public static async ValueTask<bool> SendFinalSuccessMessageAsync( Transport transport, TransportFeature remote, ulong nonce, TimeSpan finalClockOffset )
    {
        using var m = CreateAndSignMessage( nonce, finalClockOffset, remote.RemoteKeys.LocalKeys.CurrentIdentity );
        return await transport.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateAndSignMessage( ulong nonce, TimeSpan finalClockOffset, LocalIdentityKey currentIdentity )
        {
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );

            w.WriteByte( DNegoFinalSuccessMessage );
            w.WriteUInt64( nonce );
            w.WriteTimeSpan( finalClockOffset );
            ComputeSHA512HashAndAppendSignature( ref w, currentIdentity );
            return builder.CreateMessage( sequence );
        }
    }

    public static bool TryReadFinalSuccessMessage( IParallelLogger logger,
                                                   IncomingMessage message,
                                                   ulong expectedNonce,
                                                   TransportFeature remote,
                                                   out TimeSpan finalClockOffset )
    {
        Throw.DebugAssert( remote.RemoteKeys.TrustedIdentity != null );
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DNegoFinalSuccessMessage );
        if( !CheckExpectedNonce( logger, ref r, remote, expectedNonce ) )
        {
            finalClockOffset = TimeSpan.Zero;
            return false;
        }
        finalClockOffset = r.ReadTimeSpan();
        if( !ComputeSHA512HashAndVerifySignature( ref r, remote.RemoteKeys.TrustedIdentity ) )
        {
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable FinalSuccess message from '{remote.Party}'." );
            return false;
        }
        return true;
    }
}
