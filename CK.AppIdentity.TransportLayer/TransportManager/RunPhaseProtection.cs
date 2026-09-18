using CK.Core;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Per-connection integrity protection for run-phase frames: the session keys derived from the
/// handshake's ephemeral ECDH, the per-direction counters, and the MAC itself.
/// <para>
/// Authenticating the peer at connection time and stopping there is a weak model: it proves who
/// opened the connection and says nothing about the frames that follow. Without per-frame
/// protection, an on-path attacker lets the signed handshake through untouched and then injects,
/// alters, drops or replays any Blob/CRIS frame — the handshake signature never covered them.
/// </para>
/// <para>
/// It also supplies <em>channel binding</em>, which TLS cannot give here: TLS authenticates TLS
/// endpoints with TLS credentials and knows nothing of AppIdentity's key store, so a relay holding
/// two individually valid TLS connections can forward a handshake verbatim. Because the session key
/// comes from the AppIdentity handshake itself, a relay cannot derive it and every frame it forwards
/// fails its MAC.
/// </para>
/// <para>
/// This protects integrity only. Payloads stay in clear: packet readability on the wire is a
/// product requirement, not an oversight.
/// </para>
/// </summary>
public sealed class RunPhaseProtection : IDisposable
{
    /// <summary>
    /// Length of the authentication tag appended to every run-phase frame. 128 bits is ample.
    /// </summary>
    public const int TagLength = 16;

    /// <summary>
    /// Size of the derived directional keys.
    /// </summary>
    public const int KeyLength = 32;

    /// <summary>
    /// Size of the ephemeral public key on the wire (P-256 SubjectPublicKeyInfo).
    /// Bounded so a hostile peer cannot make us allocate.
    /// </summary>
    public const int MaxEphemeralPublicKeyLength = 256;

    // The GMAC nonce packs the full wire header and the frame counter: 5 + 6 + 1 reserved = 12,
    // AES-GCM's standard nonce size.
    const int MaxHeaderLength = 5;
    const int CounterLength = 6;

    /// <summary>
    /// Highest usable frame counter, imposed by the 6-byte counter field of the GMAC nonce.
    /// Roughly nine years at a million frames per second on a single connection.
    /// </summary>
    public const ulong MaxFrameCounter = (1UL << (8 * CounterLength)) - 1;

    readonly MacAlgorithm _algorithm;
    // Distinct keys per direction: this is what makes reflection (sending our own frames back to
    // us) impossible, and it gives GMAC a fresh nonce space on each side.
    readonly byte[] _sendKey;
    readonly byte[] _receiveKey;
    readonly AesGcm? _sendGcm;
    readonly AesGcm? _receiveGcm;
    // Monotonic, never transmitted: both sides count locally, so a dropped or reordered frame
    // fails its MAC automatically and costs no bytes on the wire.
    ulong _sendCounter;
    ulong _receiveCounter;
    bool _disposed;

    // Always c2l then l2c, regardless of which side we are: this makes SessionId identical on both
    // peers, which is the whole point of showing it in a log.
    readonly byte[] _c2l;
    readonly byte[] _l2c;

    RunPhaseProtection( MacAlgorithm algorithm, byte[] sendKey, byte[] receiveKey, byte[] c2l, byte[] l2c )
    {
        _algorithm = algorithm;
        _sendKey = sendKey;
        _receiveKey = receiveKey;
        _c2l = c2l;
        _l2c = l2c;
        if( algorithm == MacAlgorithm.AesGmac )
        {
            _sendGcm = new AesGcm( sendKey, TagLength );
            _receiveGcm = new AesGcm( receiveKey, TagLength );
        }
    }

    /// <summary>
    /// Gets the negotiated algorithm.
    /// </summary>
    public MacAlgorithm Algorithm => _algorithm;

    /// <summary>
    /// Gets a short, non-secret identifier of this session's keys, for diagnostics and for tests
    /// that must check that two connections derived DIFFERENT keys.
    /// <para>
    /// It is a hash of both directional keys, so it reveals nothing usable while still being
    /// unique per session.
    /// </para>
    /// </summary>
    public string SessionId
    {
        get
        {
            Span<byte> h = stackalloc byte[32];
            using var inc = IncrementalHash.CreateHash( HashAlgorithmName.SHA256 );
            inc.AppendData( "CK-AppId session id"u8 );
            inc.AppendData( _c2l );
            inc.AppendData( _l2c );
            inc.GetCurrentHash( h );
            return Convert.ToHexString( h.Slice( 0, 8 ) );
        }
    }

    /// <summary>
    /// The MAC algorithms this machine can run, as an advertisable bit set.
    /// <para>
    /// This is a hardware capability, not a preference: AES-GMAC is offered only where AES is
    /// hardware-accelerated, because software AES is both slow and cache-timing prone. Advertising
    /// a capability rather than a ranking is what keeps this from being a downgrade surface —
    /// there is no ordering for an attacker to influence, only a floor set by physics.
    /// </para>
    /// </summary>
    public static byte LocalCapabilities => (byte)(HardwareCapabilities & (_capabilityRestriction ?? 0xFF));

    /// <summary>
    /// What this machine can actually execute, ignoring any restriction.
    /// </summary>
    public static byte HardwareCapabilities
    {
        get
        {
            byte caps = 1 << (int)MacAlgorithm.HmacSha256;   // always available
            if( System.Runtime.Intrinsics.X86.Aes.IsSupported
                || System.Runtime.Intrinsics.Arm.Aes.IsSupported )
            {
                caps |= 1 << (int)MacAlgorithm.AesGmac;
            }
            return caps;
        }
    }

    static byte? _capabilityRestriction;

    /// <summary>
    /// Restricts what this process advertises. Null (the default) advertises everything the
    /// hardware supports.
    /// <para>
    /// This can only ever <em>remove</em> capabilities — the value is masked by
    /// <see cref="HardwareCapabilities"/>, so it cannot claim a primitive the machine cannot run.
    /// That is what keeps it from being a downgrade lever: restricting yourself is safe, and both
    /// primitives are strong, so the worst a restriction can do is cost performance.
    /// </para>
    /// <para>
    /// Two uses. Tests force the HMAC path so that it is exercised end to end even on hardware that
    /// would always choose GMAC — otherwise the fallback, which is the path that runs on machines
    /// without AES-NI, would never actually be run anywhere. An operator may also want it to avoid
    /// software AES on a machine whose hardware support is uncertain.
    /// </para>
    /// </summary>
    public static byte? CapabilityRestriction
    {
        get => _capabilityRestriction;
        set
        {
            Throw.CheckArgument( "At least one primitive must remain advertisable.",
                                 value == null || (HardwareCapabilities & value.Value) != 0 );
            _capabilityRestriction = value;
        }
    }

    /// <summary>
    /// Restriction value that advertises HMAC-SHA256 only.
    /// </summary>
    public const byte HmacOnly = 1 << (int)MacAlgorithm.HmacSha256;

    /// <summary>
    /// Selects the algorithm both sides can run, preferring <see cref="MacAlgorithm.AesGmac"/>.
    /// </summary>
    /// <param name="remoteCapabilities">The capability bits advertised by the peer.</param>
    /// <returns>The selected algorithm, <see cref="MacAlgorithm.Invalid"/> if there is no overlap.</returns>
    public static MacAlgorithm Select( byte remoteCapabilities )
    {
        int common = LocalCapabilities & remoteCapabilities;
        if( (common & (1 << (int)MacAlgorithm.AesGmac)) != 0 ) return MacAlgorithm.AesGmac;
        if( (common & (1 << (int)MacAlgorithm.HmacSha256)) != 0 ) return MacAlgorithm.HmacSha256;
        return MacAlgorithm.Invalid;
    }

    /// <summary>
    /// Creates the ephemeral key pair for one connection.
    /// <para>
    /// One per <see cref="Transport"/>, never cached on a <see cref="TransportFeature"/>: a reused
    /// ephemeral would reuse the session key across connections, which under GMAC is a total break
    /// rather than a degradation.
    /// </para>
    /// </summary>
    public static ECDiffieHellman CreateEphemeral() => ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );

    /// <summary>
    /// Derives the session keys.
    /// </summary>
    /// <param name="ephemeral">Our ephemeral key pair.</param>
    /// <param name="remoteEphemeralPublicKey">The peer's ephemeral SubjectPublicKeyInfo.</param>
    /// <param name="algorithm">The selected algorithm.</param>
    /// <param name="nonce">The handshake nonce, used as the HKDF salt.</param>
    /// <param name="transcript">
    /// Everything that must not be tamperable: the advertised capabilities, the selected algorithm,
    /// the protocol version and the two party names. Feeding it into the KDF rather than merely
    /// signing it means that any tampering makes the two sides derive DIFFERENT keys, so the first
    /// frame fails its MAC — it fails closed with no explicit "was this modified?" check to forget.
    /// </param>
    /// <param name="isInitiator">Which direction key is ours to send with.</param>
    public static RunPhaseProtection Derive( ECDiffieHellman ephemeral,
                                             ReadOnlySpan<byte> remoteEphemeralPublicKey,
                                             MacAlgorithm algorithm,
                                             ulong nonce,
                                             ReadOnlySpan<byte> transcript,
                                             bool isInitiator )
    {
        Throw.CheckArgument( algorithm != MacAlgorithm.Invalid );
        Throw.CheckData( remoteEphemeralPublicKey.Length > 0 && remoteEphemeralPublicKey.Length <= MaxEphemeralPublicKeyLength );

        using var remote = ECDiffieHellman.Create();
        remote.ImportSubjectPublicKeyInfo( remoteEphemeralPublicKey, out int read );
        Throw.CheckData( read == remoteEphemeralPublicKey.Length );

        var shared = ephemeral.DeriveRawSecretAgreement( remote.PublicKey );
        try
        {
            Span<byte> salt = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian( salt, nonce );

            var c2l = new byte[KeyLength];
            var l2c = new byte[KeyLength];
            HKDF.DeriveKey( HashAlgorithmName.SHA256, shared, c2l, salt, Info( transcript, "c2l"u8 ) );
            HKDF.DeriveKey( HashAlgorithmName.SHA256, shared, l2c, salt, Info( transcript, "l2c"u8 ) );

            return isInitiator
                    ? new RunPhaseProtection( algorithm, sendKey: c2l, receiveKey: l2c, c2l, l2c )
                    : new RunPhaseProtection( algorithm, sendKey: l2c, receiveKey: c2l, c2l, l2c );
        }
        finally
        {
            CryptographicOperations.ZeroMemory( shared );
        }

        static byte[] Info( ReadOnlySpan<byte> transcript, ReadOnlySpan<byte> direction )
        {
            var label = "CK-AppId v0 run-phase"u8;
            var r = new byte[label.Length + transcript.Length + direction.Length];
            label.CopyTo( r );
            transcript.CopyTo( r.AsSpan( label.Length ) );
            direction.CopyTo( r.AsSpan( label.Length + transcript.Length ) );
            return r;
        }
    }

    /// <summary>
    /// Builds the transcript bound into the key derivation.
    /// </summary>
    public static byte[] BuildTranscript( byte initiatorCapabilities,
                                          MacAlgorithm selected,
                                          int version,
                                          string initiatorFullName,
                                          string listenerFullName )
    {
        // Sized up front and encoded straight into the result: one allocation, no intermediate
        // byte[] per name and no ArrayBufferWriter. (This runs twice per connection, during the
        // handshake — not per message — so this is tidiness rather than a hot path.)
        int lenInitiator = Encoding.UTF8.GetByteCount( initiatorFullName );
        int lenListener = Encoding.UTF8.GetByteCount( listenerFullName );
        var result = new byte[3 + 4 + lenInitiator + 4 + lenListener];
        var s = result.AsSpan();
        s[0] = initiatorCapabilities;
        s[1] = (byte)selected;
        s[2] = checked((byte)version);
        int o = 3;
        // Length-prefixed, not delimiter-separated. A delimiter would make the encoding ambiguous:
        // ("A", "B/C") and ("A/B", "C") would produce the same transcript and therefore the same
        // keys, which is exactly the kind of gap a transcript exists to close.
        BinaryPrimitives.WriteInt32LittleEndian( s.Slice( o ), lenInitiator );
        o += 4;
        Encoding.UTF8.GetBytes( initiatorFullName, s.Slice( o, lenInitiator ) );
        o += lenInitiator;
        BinaryPrimitives.WriteInt32LittleEndian( s.Slice( o ), lenListener );
        o += 4;
        Encoding.UTF8.GetBytes( listenerFullName, s.Slice( o, lenListener ) );
        return result;
    }

    /// <summary>
    /// Computes the tag for the next outgoing frame and advances the send counter.
    /// </summary>
    /// <param name="header">The wire header.</param>
    /// <param name="payload">The frame payload.</param>
    /// <param name="tag">Receives <see cref="TagLength"/> bytes.</param>
    public bool SignNext( ReadOnlySpan<byte> header, in ReadOnlySequence<byte> payload, Span<byte> tag )
    {
        // A racing teardown may have disposed us between the caller reading the reference and this
        // call. Report it rather than crashing: the transport is already dying, so the frame simply
        // does not go out.
        if( _disposed ) return false;
        // Enforced, not assumed: under GMAC a repeated (key, nonce) pair with different data leaks
        // the authentication subkey and allows arbitrary forgery, so a counter that ran past the
        // nonce's 6-byte field must stop the connection rather than wrap into a reused nonce.
        // Unreachable in practice — see MaxFrameCounter — which is exactly why it must be checked
        // rather than trusted.
        Throw.CheckState( "Frame counter exhausted: the connection must be re-established to rekey.",
                          _sendCounter < MaxFrameCounter );
        ComputeTag( sending: true, _sendCounter, header, payload, tag );
        // Monotonic and never reused.
        checked { ++_sendCounter; }
        return true;
    }

    /// <summary>
    /// Verifies the tag of the next incoming frame and advances the receive counter on success.
    /// <para>
    /// The counter is not transmitted, so a replayed, reordered or dropped frame simply fails here.
    /// </para>
    /// </summary>
    /// <returns>True if the frame is authentic and in order.</returns>
    public bool VerifyNext( ReadOnlySpan<byte> header, in ReadOnlySequence<byte> payload, ReadOnlySpan<byte> tag )
    {
        if( _disposed ) return false;
        if( tag.Length != TagLength ) return false;
        if( _receiveCounter >= MaxFrameCounter ) return false;
        Span<byte> expected = stackalloc byte[TagLength];
        ComputeTag( sending: false, _receiveCounter, header, payload, expected );
        if( !CryptographicOperations.FixedTimeEquals( expected, tag ) ) return false;
        checked { ++_receiveCounter; }
        return true;
    }

    void ComputeTag( bool sending, ulong counter, ReadOnlySpan<byte> header, in ReadOnlySequence<byte> payload, Span<byte> tag )
    {
        if( _algorithm == MacAlgorithm.AesGmac )
        {
            var gcm = sending ? _sendGcm : _receiveGcm;
            Throw.DebugAssert( gcm != null );
            // GMAC nonce: [header: 5 bytes, zero-padded][counter: 6 bytes][1 reserved] = 12, which
            // is AES-GCM's standard nonce size.
            //
            // Packing the header into the nonce rather than into the authenticated data leaves the
            // AAD equal to the payload alone, so a single-segment frame authenticates with NO copy.
            // AesGcm requires contiguous associated data, and gathering counter+header+payload cost
            // 10-37% on top of the MAC itself — worst on small frames, which are the common ones.
            //
            // The header is covered in FULL here, including its declared-length bytes. It would
            // have been tempting to carry only the flag byte and argue that a tampered length is
            // caught anyway, since it changes how many payload bytes the receiver feeds in — true,
            // but implicit. Everything the tag depends on is covered explicitly instead.
            // Zero-padding cannot merge two different headers: byte 0 encodes the length size, so
            // headers of different lengths already differ in byte 0.
            //
            // The counter is 6 bytes instead of 8 to make room. 2^48 frames on one connection is
            // roughly nine years at a million frames a second; SignNext guards the bound rather
            // than letting it wrap silently, because a wrapped counter under GMAC means a repeated
            // (key, nonce) pair, which is a total break.
            Throw.DebugAssert( header.Length <= MaxHeaderLength );
            Span<byte> nonce = stackalloc byte[12];
            nonce.Clear();
            header.CopyTo( nonce );                                  // [0..5) header, zero-padded
            Span<byte> c = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian( c, counter );
            c.Slice( 0, CounterLength ).CopyTo( nonce.Slice( MaxHeaderLength ) );   // [5..11) counter
            // Authenticated data only: the payload is NOT encrypted (it must stay readable).
            if( payload.IsSingleSegment )
            {
                gcm.Encrypt( nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, payload.FirstSpan );
            }
            else
            {
                // Multi-segment: AesGcm has no incremental API, so this one must be gathered.
                int len = checked((int)payload.Length);
                var buffer = ArrayPool<byte>.Shared.Rent( len );
                try
                {
                    payload.CopyTo( buffer );
                    gcm.Encrypt( nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, buffer.AsSpan( 0, len ) );
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return( buffer );
                }
            }
        }
        else
        {
            using var h = IncrementalHash.CreateHMAC( HashAlgorithmName.SHA256, sending ? _sendKey : _receiveKey );
            Span<byte> c = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian( c, counter );
            h.AppendData( c );
            h.AppendData( header );
            foreach( var s in payload ) h.AppendData( s.Span );
            Span<byte> full = stackalloc byte[32];
            h.GetCurrentHash( full );
            full.Slice( 0, TagLength ).CopyTo( tag );
        }
    }

    public void Dispose()
    {
        if( _disposed ) return;
        _disposed = true;
        _sendGcm?.Dispose();
        _receiveGcm?.Dispose();
        CryptographicOperations.ZeroMemory( _sendKey );
        CryptographicOperations.ZeroMemory( _receiveKey );
    }
}
