using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    static partial class ZeroProtocol // Negotiation
    {
        public const int FirstAnswerMaxLength = 1 // One byte discriminator.
                                                + 5 // Number of common protocol (allows uint.MaxValue even if it's caped by MessageProtocolMap.MaxCount)
                                                + MessageProtocolMap.MaxCount * (2 * MessageProtocol.FullNameMaxLength);

        // Static messages use no initialization lock (we don't care of the rare case where 2 concurrent messages will be instantiated).
        // DNegoDowngradeProtocol followed by our CurrentVersion: it can be static.
        static IOutgoingMessage? _downgradeProtocolReplyMessage;
        // DNegoFinalFailureMessage: it can be static.
        static IOutgoingMessage? _finalFailureMessage;

        public enum ConfigurationOrTrustIssue : byte
        {
            Unknwon = 0,
            DisallowedTransport = 1,
            InvalidClockOffset = 2,
            InitiatorConflict = 3,
            UnsupportedTransport = 4,
            ListenerRequiresLocalApproval = 5,
            ListenerRequiresRemoteApproval = 6,
            RequiresBothApproval = 7,

            MaxValue = 7
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
        /// Writes the identity keys (public parts), computes a SHA512 hash and writes the computed
        /// signatures for all the identities.
        /// </summary>
        /// <param name="w">The writer.</param>
        /// <param name="sequence">The sequence being written.</param>
        /// <param name="localIdentities">The identity keys to write.</param>
        static void WriteIdentityKeysAndSign( ref FastByteWriter w, MutableSequence<byte> sequence, IReadOnlyList<LocalIdentityKey> localIdentities )
        {
            // Independent serialization version for the identities and signatures.
            w.WriteSmallUInt32( 0 );
            // Writes the identity keys.
            WriteIdentityKeys( ref w, localIdentities );
            w.Commit();
            // Appends the signatures.
            ComputeSHA512HashAndAppendAllSignatures( ref w, sequence, localIdentities );
            w.Commit();

            static void WriteIdentityKeys( ref FastByteWriter w, IReadOnlyList<LocalIdentityKey> localIdentities )
            {
                w.WriteSmallUInt32( (uint)localIdentities.Count );
                foreach( var k in localIdentities )
                {
                    w.WriteDateTime( k.TimeName );
                    w.WriteSmallUInt32( (uint)k.PublicKeyRawData.Length );
                    w.WriteBytes( k.PublicKeyRawData.Span );
                }
            }

            static void ComputeSHA512HashAndAppendAllSignatures( ref FastByteWriter w, MutableSequence<byte> sequence, IReadOnlyList<LocalIdentityKey> localIdentities )
            {
                Span<byte> messageHash = stackalloc byte[64];
                Span<byte> signature = stackalloc byte[256];
                ComputeHash( sequence.GetReadOnlySequence(), messageHash );
                foreach( var i in localIdentities )
                {
                    Throw.CheckData( i.TrySignHash( messageHash, signature, out int byteWritten ) );
                    w.WriteByte( (byte)byteWritten );
                    w.WriteBytes( signature.Slice( 0, byteWritten ) );
                }
            }
        }

        /// <summary>
        /// Reads the identity keys written by <see cref="WriteIdentityKeysAndSign(ref FastByteWriter, MutableSequence{byte}, IReadOnlyList{LocalIdentityKey})"/>,
        /// verifies the signature against the <paramref name="alreadyTrusted"/> if we have it or against the remote's current one.
        /// </summary>
        /// <param name="r">The reader.</param>
        /// <param name="alreadyTrusted">Optional trusted key.</param>
        /// <param name="foundTrustedKey">True if the <paramref name="alreadyTrusted"/> has been found in the keys.</param>
        /// <param name="currentKeyData">Outputs the current key data. This is always computed.</param>
        /// <param name="currentKey">Outputs the remote's current key if it was needed to verify the signature (when the trusted key has not been found).</param>
        /// <returns>True is the signature's message has been verified, false otherwise.</returns>
        public static bool ReadIdentityKeysAndVerifySignatures( ref FastByteReader r,
                                                                RemoteIdentityKey? alreadyTrusted,
                                                                out bool foundTrustedKey,
                                                                out RemoteIdentityKeyData currentKeyData,
                                                                out RemoteIdentityKey? currentKey )
        {
            Throw.CheckData( r.ReadSmallUInt32() == 0 ); // Version.
            var keyCount = r.ReadSmallUInt32();
            Throw.CheckData( keyCount >= 1 && keyCount <= ILocalKeys.MaxIdentityCount );
            // If we have a trusted identity, it is the one we'll use to verify the signature, and if it is the current one,
            // it is fine. If it is no more the current one, we create and returns the current one.
            //
            // If we have no trusted identity, we create the current one and uses it to validate the signature.
            foundTrustedKey = false;
            uint idxSignatureToVerify = 0;
            currentKey = null;

            var reusableBuffer = ArrayPool<byte>.Shared.Rent( ILocalKeys.MaxPublicKeySize );
            try
            {
                // Reads the current one.
                var timeName = r.ReadDateTime();
                var lenPublicKey = r.ReadSmallUInt32();
                Throw.CheckData( lenPublicKey <= ILocalKeys.MaxPublicKeySize );
                var publicRawData = reusableBuffer.AsSpan( 0, (int)lenPublicKey );
                r.ReadBytes( publicRawData );
                if( alreadyTrusted != null && alreadyTrusted.Equals( timeName, publicRawData ) )
                {
                    // Fast path: the current one is the already trusted one.
                    // We can skip the remaining keys.
                    foundTrustedKey = true;
                    currentKey = alreadyTrusted;
                    currentKeyData = currentKey.GetKeyData();
                    SkipRemainingKeys( ref r, keyCount, reusableBuffer );
                }
                else
                {
                    var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo( publicRawData, out int bytesRead );
                    Throw.CheckData( bytesRead == publicRawData.Length );
                    currentKeyData = new RemoteIdentityKeyData( timeName, publicKey );
                    // If we have no already trusted key then we need the current to verify the signature
                    // and we can skip the remaining keys.
                    if( alreadyTrusted == null )
                    {
                        currentKey = new RemoteIdentityKey( currentKeyData );
                        SkipRemainingKeys( ref r, keyCount, reusableBuffer );
                    }
                    else
                    {
                        // We must find our trusted key and it is not the first one.
                        while( ++idxSignatureToVerify < keyCount )
                        {
                            timeName = r.ReadDateTime();
                            lenPublicKey = r.ReadSmallUInt32();
                            Throw.CheckData( lenPublicKey <= ILocalKeys.MaxPublicKeySize );
                            publicRawData = reusableBuffer.AsSpan( 0, (int)lenPublicKey );
                            r.ReadBytes( publicRawData );
                            if( alreadyTrusted.Equals( timeName, publicRawData ) )
                            {
                                // Found it!
                                // We can skip the remaining keys.
                                foundTrustedKey = true;
                                SkipRemainingKeys( ref r, keyCount - idxSignatureToVerify, reusableBuffer );
                                break;
                            }
                        }
                        // If we haven't found our trusted key, we use the remote's current one.
                        if( !foundTrustedKey )
                        {
                            idxSignatureToVerify = 0;
                            currentKey = new RemoteIdentityKey( currentKeyData );
                        }
                    }
                }
                // End of the message: it's time to compute its hash.
                // We use the reusableBuffer: 64 first bytes for the hash, 256 next bytes
                // for the idxSignatureToVerify signature buffer.
                Throw.DebugAssert( reusableBuffer.Length >= 64 );
                var hashData = reusableBuffer.AsSpan( 0, 64 );
                var signatureBuffer = reusableBuffer.AsSpan( 64, 256 );
                ComputeHash( r.GetBeforeHead(), hashData );
                // Find the signature that must be checked (forget the first ones).
                Span<byte> signature = default;
                for( int i = 0; i <= idxSignatureToVerify; i++ )
                {
                    // We could have settled the signature size (we use DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
                    // but it doesn't cost much (1 byte) to let it variable so that are free to use different key size (the
                    // current default is 256 bits (ECDsa creates signatures of 2 x KeySize: this is 2 * 256 / 8 = 64 bytes for
                    // current key size) and this should be enough... but who knows, so let the max signature size be 255 bytes).
                    var lenSignature = r.ReadByte();
                    signature = signatureBuffer.Slice( 0, lenSignature );
                    r.ReadBytes( signature );
                }
                var verifier = foundTrustedKey ? alreadyTrusted : currentKey;
                Throw.DebugAssert( verifier != null );
                return verifier.VerifyHash( hashData, signature );
            }
            finally
            {
                ArrayPool<byte>.Shared.Return( reusableBuffer );
            }

            static void SkipRemainingKeys( ref FastByteReader r, uint keyCount, byte[] keyBuffer )
            {
                while( --keyCount > 0 )
                {
                    r.ReadDateTime();
                    var len = r.ReadSmallUInt32();
                    Throw.CheckData( len <= ILocalKeys.MaxPublicKeySize );
                    var forget = keyBuffer.AsSpan( 0, (int)len );
                    r.ReadBytes( forget );
                }
            }
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
        public static async ValueTask<ulong?> SendInitialMessageAsync( ISystemClock systemClock, Transport transport, InitialMessage initialMessage, int version )
        {
            using var m = CreateAndSignMessage( systemClock, initialMessage, version, out var nonce );
            if( !await transport.SendAsync( 0, m ).ConfigureAwait( false ) ) return null;
            return nonce;

            static IOutgoingMessage CreateAndSignMessage( ISystemClock systemClock, InitialMessage initialMessage, int version, out ulong nonce )
            {
                Throw.DebugAssert( initialMessage.LocalIdentities.Count > 0 );
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );

                // There is currently only one version.
                Throw.CheckArgument( version == CurrentVersion );
                // Writes the message content (cuurent version).
                initialMessage.WriteCurrentVersion( ref w );

                // Writes the nonce (creation time and 64 bits nonce) ang gets its value:
                // the creation time will be used to compute the clock offset and the nonce value will
                // be reused for the subsequent messages during this negotiation.
                nonce = CreateAndWriteNonce( ref w, systemClock ).Nonce;
                // Writes the identity keys and sign the message with them.
                WriteIdentityKeysAndSign( ref w, sequence, initialMessage.LocalIdentities );
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
                    WriteIdentityKeysAndSign( ref w, sequence, remoteKeys.LocalKeys.Identities );
                }
                return builder.CreateMessage( sequence );
            }
        }

        public static void ReadRejectRemoteReplyMessage( IncomingMessage message,
                                                         ulong expectedNonce,
                                                         RemoteIdentityKey? trustedIdentity,
                                                         out bool nonceFailure,
                                                         out ConfigurationOrTrustIssue issue,
                                                         out TimeSpan? clockOffset,
                                                         out string? enlistUrl,
                                                         out RemoteIdentityKeyData? currentKeyData,
                                                         out bool foundTrustedKey,
                                                         out RemoteIdentityKey? currentKey,
                                                         out bool signatureVerified )
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
                signatureVerified = ReadIdentityKeysAndVerifySignatures( ref r, trustedIdentity, out foundTrustedKey, out currentKeyData, out currentKey );
            }
            else
            {
                signatureVerified = false;
                foundTrustedKey = false;
                currentKeyData = null;
                currentKey = null;
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
            using var m = CreateAndSignMessage( nonce, clockOffset, offMessage, transport.RemoteKeys.LocalKeys.Identities );
            return await transport.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( ulong nonce, TimeSpan clockOffset, GoodbyeMessage offMessage, IReadOnlyList<LocalIdentityKey> localIdentities )
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
                WriteIdentityKeysAndSign( ref w, sequence, localIdentities );
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
            if( ReadIdentityKeysAndVerifySignatures( ref r,
                                                     remote.RemoteKeys.TrustedIdentity,
                                                     out var foundTrustedKey,
                                                     out var currentKeyData,
                                                     out var currentKey ) )
            {
                logger.Info( $"Received verified Remote Off message from '{remote.RemoteKeys.Party}': {offMessage}." );
                remote.RemoteKeys.OnReadIdentityKeys( logger, foundTrustedKey, currentKeyData, currentKey );
                return true;
            }
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable Remote Off message from '{remote.RemoteKeys.Party}'." );
            return false;
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

        public static int ReadDowngradeProtocolReplyMessage( IncomingMessage message )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Throw.DebugAssert( discriminator == DNegoDowngradeProtocol );
            return (int)r.ReadSmallUInt32();
        }

        public static async ValueTask<bool> SendAcceptedProtocolsMessageAsync( ISystemClock systemClock,
                                                                               Transport transport,
                                                                               MessageProtocolMap protocolMap,
                                                                               ulong nonce,
                                                                               TimeSpan initialClockOffset )
        {
            Throw.DebugAssert( transport.RemoteKeys != null );
            using var m = CreateAndSignMessage( systemClock, protocolMap, nonce, initialClockOffset, transport.RemoteKeys.LocalKeys.Identities );
            return await transport.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( ISystemClock systemClock,
                                                          in MessageProtocolMap protocolMap,
                                                          ulong nonce,
                                                          TimeSpan initialClockOffset,
                                                          IReadOnlyList<LocalIdentityKey> localIdentities )
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
                WriteIdentityKeysAndSign( ref w, sequence, localIdentities );
                return builder.CreateMessage( sequence );
            }
        }

        public static MessageProtocolMap TryReadAcceptedProtocolsMessage( TransportManager transportManager,
                                                                          IncomingMessage message,
                                                                          TransportFeature remote,
                                                                          ulong expectedNonce,
                                                                          out bool foundTrustedKey,
                                                                          out TimeSpan currentClockOffset )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Throw.DebugAssert( discriminator == DNegoAcceptedProtocolsMessage );
            foundTrustedKey = false;
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
            var map = MessageProtocolMap.InternalGet( protocols );
            if( ReadIdentityKeysAndVerifySignatures( ref r,
                                                     remote.RemoteKeys.TrustedIdentity,
                                                     out foundTrustedKey,
                                                     out var currentKeyData,
                                                     out var currentKey ) )
            {
                transportManager.Logger.Info( $"Received verified AcceptedProtocolsMessage message from '{remote.Party}'." );
                foundTrustedKey |= remote.RemoteKeys.OnReadIdentityKeys( transportManager.Logger, foundTrustedKey, currentKeyData, currentKey );
                if( !foundTrustedKey )
                {
                    return default;
                }
                var missingProtocols = remote.BestRegisteredProtocols.Where( b => !protocols.Any( p => p.Name == b.Name ) );
                if( missingProtocols.Any() )
                {
                    transportManager.Logger.Error( $"Remote '{remote.Party.FullName}' cannot support protocols: '{missingProtocols.Select( p => p.FullName ).Concatenate( "' ,'" )}'." );
                    return default;
                }
                return map;
            }
            transportManager.Logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable AcceptedProtocolsMessage message from '{remote.Party}'." );
            return default;

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
            using var m = CreateAndSignMessage( nonce, incoming.RemoteKeys.LocalKeys.Identities );
            return await incoming.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( ulong nonce, IReadOnlyList<LocalIdentityKey> localIdentities )
            {
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );

                w.WriteByte( DNegoEvictionDisallowed );
                w.WriteUInt64( nonce );
                WriteIdentityKeysAndSign( ref w, sequence, localIdentities );
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
            if( ReadIdentityKeysAndVerifySignatures( ref r,
                                                     remote.RemoteKeys.TrustedIdentity,
                                                     out var foundTrustedKey,
                                                     out var currentKeyData,
                                                     out var currentKey ) )
            {
                logger.Info( $"Received verified Eviction Disallowed message from '{remote.RemoteKeys.Party}'." );
                remote.RemoteKeys.OnReadIdentityKeys( logger, foundTrustedKey, currentKeyData, currentKey );
                return true;
            }
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable Eviction Disallowed message from '{remote.RemoteKeys.Party}'." );
            return false;
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
            using var m = CreateAndSignMessage( nonce, weAreMissing, heIsMissing, incoming.RemoteKeys.LocalKeys.Identities );
            return await incoming.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( ulong nonce, List<string>? weAreMissing, List<string>? heIsMissing, IReadOnlyList<LocalIdentityKey> localIdentities )
            {
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );

                w.WriteByte( DNegoMissingProtocols );
                w.WriteUInt64( nonce );
                WriteMissing( ref w, weAreMissing );
                WriteMissing( ref w, heIsMissing );

                WriteIdentityKeysAndSign( ref w, sequence, localIdentities );
                return builder.CreateMessage( sequence );

                static void WriteMissing( ref FastByteWriter w, List<string>? missing )
                {
                    uint ourCount = missing != null ? (uint)missing.Count : 0;
                    w.WriteSmallUInt32( ourCount );
                    if( ourCount != 0 )
                    {
                        Throw.DebugAssert( missing != null );
                        foreach( var p in missing )
                        {
                            w.WriteString( p );
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
            if( ReadIdentityKeysAndVerifySignatures( ref r,
                                                     remote.RemoteKeys.TrustedIdentity,
                                                     out var foundTrustedKey,
                                                     out var currentKeyData,
                                                     out var currentKey ) )
            {
                logger.Info( $"Received verified MissingProtocols message from '{remote.Party}'." );
                remote.RemoteKeys.OnReadIdentityKeys( logger, foundTrustedKey, currentKeyData, currentKey );
                return true;
            }
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable MissingProtocols message from '{remote.Party}'." );
            return false;

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
}
