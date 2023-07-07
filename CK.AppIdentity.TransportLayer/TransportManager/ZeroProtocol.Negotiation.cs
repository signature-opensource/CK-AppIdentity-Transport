using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer
{
    static partial class ZeroProtocol
    {
        public const int FirstAnswerMaxLength = 1 // One byte discriminator.
                                                + 5 // Number of common protocol (allows uint.MaxValue even if it's caped by MessageProtocolMap.MaxCount)
                                                + MessageProtocolMap.MaxCount * (2 * MessageProtocol.FullNameMaxLength);

        // Static messages use no initialization lock (we don't care of the rare case where 2 concurrent messages will be instantiated).
        // "1" followed by our version: it can be static.
        static IOutgoingMessage? _downgradeProtocolReplyMessage;
        // The DiscriminatorFinalMessage with a single "1": it can be static.
        static IOutgoingMessage? _finalSuccessMessage;
        // The DiscriminatorFinalMessage with a single "0": it can be static.
        static IOutgoingMessage? _finalFailureMessage;
        // The DiscriminatorEvictionDisallowed: it can be static.
        static IOutgoingMessage? _evictionDisallowedMessage;

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
                Debug.Assert( reusableBuffer.Length >= 64 );
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
                    // current key size) and this should be enough... but who knows, so let the max signature size be 256 bytes).
                    var lenSignature = r.ReadByte();
                    signature = signatureBuffer.Slice( 0, lenSignature );
                    r.ReadBytes( signature );
                }
                var verifier = foundTrustedKey ? alreadyTrusted : currentKey;
                Debug.Assert( verifier != null );
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
        /// Tries to send a TransportMessage of the <see cref="TransportFeature.OutgoingInitialMessage"/> in a specific version.
        /// </summary>
        /// <param name="transport">The newly created transport.</param>
        /// <param name="initialMessage">The <see cref="TransportFeature.OutgoingInitialMessage"/>.</param>
        /// <param name="version">The serialization version.</param>
        /// <returns>False if <see cref="Transport.IsCondemned"/> has been signaled or if the <paramref name="version"/> is not locally supported.</returns>
        public static async ValueTask<bool> SendInitialMessageAsync( Transport transport, InitialMessage initialMessage, int version )
        {
            using var m = CreateAndSignMessage( initialMessage, version );
            return await transport.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( InitialMessage initialMessage, int version )
            {
                Debug.Assert( initialMessage.LocalIdentities.Count > 0 );
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );
                // There is currently only one version.
                Throw.CheckArgument( version == CurrentVersion );
                // Writes the message content.
                initialMessage.WriteCurrentVersion( ref w );
                // Writes the nonce (64 bits).
                Span<byte> nonce = stackalloc byte[8];
                RandomNumberGenerator.Fill( nonce );
                w.WriteBytes( nonce );
                // Writes the DateTime.UtcNow of this system.
                w.WriteDateTime( DateTime.UtcNow );
                // Writes the identity keys and sign the message with them.
                WriteIdentityKeysAndSign( ref w, sequence, initialMessage.LocalIdentities );
                return builder.CreateMessage( sequence );
            }
        }

        static void ComputeSHA512HashAndAppendSignature( ref FastByteWriter w, MutableSequence<byte> bytes, LocalIdentityKey identityKey )
        {
            Span<byte> messageHash = stackalloc byte[64];
            Span<byte> signature = stackalloc byte[256];
            ComputeHash( bytes.GetReadOnlySequence(), messageHash );
            Throw.CheckData( identityKey.TrySignHash( messageHash, signature, out int byteWritten ) );
            w.WriteByte( (byte)byteWritten );
            w.WriteBytes( signature.Slice( 0, byteWritten ) );
            w.Commit();
        }

        internal static void ComputeHash( ReadOnlySequence<byte> message, Span<byte> hash )
        {
            using var h = IncrementalHash.CreateHash( HashAlgorithmName.SHA512 );
            foreach( var s in message )
            {
                h.AppendData( s.Span );
            }
            h.GetCurrentHash( hash );
        }

        public static async ValueTask<bool> SendUnknownRemoteReplyMessageAsync( Transport transport,
                                                                                string? enlistUrl,
                                                                                bool signatureVerificationFailed )
        {
            using var m = CreateMessage( transport, enlistUrl, signatureVerificationFailed );
            return await transport.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateMessage( Transport transport, string? userAcceptUri, bool signatureVerificationFailed )
            {
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );
                w.WriteByte( DNegoUnknownRemote );
                w.WriteBool( signatureVerificationFailed );
                if( signatureVerificationFailed )
                {
                    w.Commit();
                }
                else
                {
                    w.WriteNullableString( userAcceptUri );
                    // When the incoming remote is not known at all, we don't have local
                    // keys (we cannot locate the local party to use so we take no risk: selecting the root
                    // ApplicationIdentityService local is not a good idea).
                    if( transport.LocalKeys == null )
                    {
                        w.WriteBool( false );
                        w.Commit();
                    }
                    else
                    {
                        w.WriteBool( true );
                        WriteIdentityKeysAndSign( ref w, sequence, transport.LocalKeys.Identities );
                    }
                }
                return builder.CreateMessage( sequence );
            }
        }

        public static void ReadUnknownRemoteReplyMessage( IncomingMessage message,
                                                          RemoteIdentityKey? trustedIdentity,
                                                          out bool remoteVerificationFailure,
                                                          out string? enlistUrl,
                                                          out RemoteIdentityKeyData? currentKeyData,
                                                          out bool foundTrustedKey,
                                                          out RemoteIdentityKey? currentKey,
                                                          out bool signatureVerified )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DNegoUnknownRemote );
            remoteVerificationFailure = r.ReadBool();
            if( remoteVerificationFailure )
            {
                enlistUrl = null;
                signatureVerified = false;
                foundTrustedKey = false;
                currentKeyData = null;
                currentKey = null;
                return;
            }
            enlistUrl = r.ReadNullableString();
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
            Debug.Assert( discriminator == DNegoDowngradeProtocol );
            return (int)r.ReadSmallUInt32();
        }

        public static async ValueTask<bool> SendAcceptedProtocolsMessageAsync( Transport transport, MessageProtocolMap protocolMap )
        {
            Debug.Assert( transport.LocalKeys != null );
            using var m = CreateAndSignMessage( protocolMap, transport.LocalKeys.Identities );
            return await transport.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( in MessageProtocolMap protocolMap, IReadOnlyList<LocalIdentityKey> localIdentities )
            {
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );

                w.WriteByte( DNegoAcceptedProtocolsMessage );
                w.WriteSmallUInt32( (uint)protocolMap.Protocols.Count );
                foreach( var p in protocolMap.Protocols )
                {
                    w.WriteString( p.FullName );
                }
                w.Commit();

                WriteIdentityKeysAndSign( ref w, sequence, localIdentities );
                return builder.CreateMessage( sequence );
            }
        }

        public static MessageProtocolMap TryReadAcceptedProtocolsMessage( IParallelLogger logger, IncomingMessage message, TransportFeature remote )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DNegoAcceptedProtocolsMessage );
            uint count = r.ReadSmallUInt32();
            if( count > MessageProtocolMap.MaxCount )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' returned {count} protocols, MessageProtocolMap.MaxCount is {MessageProtocolMap.MaxCount}." );
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
                    logger.Error( $"Remote '{remote.Party.FullName}' returned an unwanted protocol '{fullName}'." );
                    return default;
                }
                protocols[i] = p;
            }
            var missing = remote.BestRegisteredProtocols.Where( b => !protocols.Any( p => p.Name == b.Name ) );
            if( missing.Any() )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' cannot support protocols: '{missing.Select( p => p.FullName ).Concatenate("' ,'")}'." );
                return default;
            }
            var map = MessageProtocolMap.InternalGet( protocols );
            if( ReadIdentityKeysAndVerifySignatures( ref r,
                                         remote.RemoteKeys.TrustedIdentity,
                                         out var foundTrustedKey,
                                         out var currentKeyData,
                                         out var currentKey ) )
            {
                logger.Info( $"Received verified AcceptedProtocolsMessage message from '{remote.Party}'." );
                remote.RemoteKeys.OnReadIdentityKeys( logger, foundTrustedKey, currentKeyData, currentKey );
                return map;
            }
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable AcceptedProtocolsMessage message from '{remote.Party}'." );
            return default;

        }

        /// <summary>
        /// Message sent by the <see cref="IncomingConnectionBackTask"/> when the transport is valid
        /// but <see cref="TransportFeature.DisallowEviction"/> is false.
        /// </summary>
        /// <param name="incoming">The transport.</param>
        /// <returns>The awaitable.</returns>
        public static ValueTask<bool> SendEvictionDisallowedMessageAsync( Transport incoming )
        {
            var m = _evictionDisallowedMessage ??= _zeroFactory.CreateStatic( bytes =>
            {
                var b = bytes.GetSpan( 1 );
                b[0] = DNegoEvictionDisallowed;
            } );
            return incoming.SendAsync( 0, m );
        }

        /// <summary>
        /// Message sent by the <see cref="IncomingConnectionBackTask"/> when the initial message of the remote misses some
        /// of our protocols.
        /// </summary>
        /// <param name="incoming">The transport.</param>
        /// <param name="missingProtocols">The missing protocols.</param>
        /// <returns>The awaitable.</returns>
        public static async ValueTask<bool> SendMissingProtocolsMessageAsync( Transport incoming, IReadOnlyList<MessageProtocol> missingProtocols )
        {
            Debug.Assert( incoming.LocalKeys != null );
            using var m = CreateAndSignMessage( missingProtocols, incoming.LocalKeys.Identities );
            return await incoming.SendAsync( 0, m ).ConfigureAwait( false );

            static IOutgoingMessage CreateAndSignMessage( IReadOnlyList<MessageProtocol> missingProtocols, IReadOnlyList<LocalIdentityKey> localIdentities )
            {
                var builder = _zeroFactory.CreateBuilder();
                var sequence = builder.ObtainSequence();
                var w = new FastByteWriter( sequence );

                w.WriteByte( DNegoMissingProtocols );
                w.WriteSmallUInt32( (uint)missingProtocols.Count );
                foreach( var p in missingProtocols )
                {
                    w.WriteString( p.FullName );
                }
                w.Commit();

                WriteIdentityKeysAndSign( ref w, sequence, localIdentities );
                return builder.CreateMessage( sequence );
            }
        }

        public static string[]? TryReadMissingProtocolsMessage( IParallelLogger logger, IncomingMessage message, TransportFeature remote )
        {
            var r = new FastByteReader( message.Message );
            var discriminator = r.ReadByte();
            Debug.Assert( discriminator == DNegoMissingProtocols );
            uint count = r.ReadSmallUInt32();
            if( count > MessageProtocolMap.MaxCount )
            {
                logger.Error( $"Remote '{remote.Party.FullName}' returned {count} missing protocols, MessageProtocolMap.MaxCount is {MessageProtocolMap.MaxCount}." );
                return null;
            }
            var missingProtocols = new string[count];
            for( int i = 0; i < count; ++i )
            {
                missingProtocols[i] = r.ReadString( MessageProtocol.FullNameMaxLength );
            }
            if( ReadIdentityKeysAndVerifySignatures( ref r,
                                             remote.RemoteKeys.TrustedIdentity,
                                             out var foundTrustedKey,
                                             out var currentKeyData,
                                             out var currentKey ) )
            {
                logger.Info( $"Received verified MissingProtocols message from '{remote.Party}'." );
                remote.RemoteKeys.OnReadIdentityKeys( logger, foundTrustedKey, currentKeyData, currentKey );
                return missingProtocols;
            }
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable MissingProtocols message from '{remote.Party}'." );
            return null;
        }

        public static ValueTask<bool> SendFinalMessageAsync( Transport transport, TransportFeature remote, bool value )
        {
            IOutgoingMessage m = value
                    ? _finalSuccessMessage ??= _zeroFactory.CreateStatic( bytes =>
                    {
                        var m = bytes.GetSpan( 2 );
                        m[0] = DNegoFinalMessage;
                        m[1] = 1;
                        bytes.Advance( 2 );
                    } )
                    : _finalFailureMessage ??= _zeroFactory.CreateStatic( bytes =>
                    {
                        var m = bytes.GetSpan( 2 );
                        m[0] = DNegoFinalMessage;
                        m[1] = 0;
                        bytes.Advance( 2 );
                    } );
            return transport.SendAsync( 0, m );
        }
    }
}
