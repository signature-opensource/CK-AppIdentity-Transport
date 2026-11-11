using CK.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// A statement signed by a party (<see cref="ILocalKeys.Sign"/>) that carries the last events of the signer's key event log
/// (up to <see cref="KeyEventChain.MaxEventWindow"/>): a party that anchors the signer (see <see cref="ILocalKeys.TrustAnchors"/>)
/// verifies it with nothing else, whatever the path it took (no connection, no fetch). A hop can withhold it, not forge it.
/// <para>
/// The signature covers the <see cref="Purpose"/> and the <see cref="Data"/>, until its expiration. The events are not
/// signed by the statement: each one proves itself, and they are verified from the anchor (or from the keys held).
/// </para>
/// </summary>
public sealed class AnchoredStatement
{
    const byte Version = 0;

    /// <summary>
    /// The maximal length of <see cref="Data"/>.
    /// </summary>
    public const int MaxDataLength = 4096;

    /// <summary>
    /// The maximal length of an encoded statement.
    /// </summary>
    public const int MaxEncodedSize = 1 // Version.
                                      + 4 + 3 * CoreApplicationIdentity.FullNameMaxLength // The signer.
                                      + 4 + ApplicationSignature.MaxPurposeLength
                                      + 4 + MaxDataLength
                                      + 4 + KeyEventChain.MaxEventWindow * (4 + KeyEvent.MaxEncodedSize)
                                      + 4 + 3 + OperationalCredential.MaxEncodedSize + ApplicationSignature.SignatureSize;

    readonly byte[] _data;
    readonly KeyEvent[] _events;

    AnchoredStatement( string signerFullName, string purpose, byte[] data, KeyEvent[] events, ApplicationSignature signature )
    {
        SignerFullName = signerFullName;
        Purpose = purpose;
        _data = data;
        _events = events;
        Signature = signature;
    }

    /// <summary>
    /// Gets the full name of the party that signed the statement.
    /// </summary>
    public string SignerFullName { get; }

    /// <summary>
    /// Gets the purpose of the signature.
    /// </summary>
    public string Purpose { get; }

    /// <summary>
    /// Gets the signed data.
    /// </summary>
    public ReadOnlyMemory<byte> Data => _data;

    /// <summary>
    /// Gets the last events of the signer's key event log, oldest first.
    /// </summary>
    public IReadOnlyList<KeyEvent> Events => _events;

    /// <summary>
    /// Gets the signature.
    /// </summary>
    public ApplicationSignature Signature { get; }

    /// <summary>
    /// Gets the expiration of the signature (signed: trust it only once verified).
    /// </summary>
    public DateTime Expiration => Signature.Expiration;

    /// <summary>
    /// Signs a statement with the keys of a local party: its last events (up to <see cref="KeyEventChain.MaxEventWindow"/>)
    /// are carried by the statement.
    /// </summary>
    /// <param name="signer">The keys of the signer.</param>
    /// <param name="purpose">The purpose of the signature.</param>
    /// <param name="data">The data (at most <see cref="MaxDataLength"/> bytes).</param>
    /// <param name="expiration">The expiration of the signature (at most <see cref="ILocalKeys.MaxSignatureDays"/> ahead).</param>
    /// <returns>The statement.</returns>
    public static AnchoredStatement Create( ILocalKeys signer, string purpose, ReadOnlySpan<byte> data, DateTime expiration )
    {
        Throw.CheckNotNullArgument( signer );
        Throw.CheckArgument( data.Length <= MaxDataLength );
        var log = signer.State.Log;
        var events = log.AsSpan( Math.Max( 0, log.Length - KeyEventChain.MaxEventWindow ) ).ToArray();
        var signature = signer.Sign( purpose, data, expiration );
        return new AnchoredStatement( signer.Party.FullName.Path, purpose, data.ToArray(), events, signature );
    }

    /// <summary>
    /// Verifies the statement with the keys of its signer as a local party holds them: the anchored ones
    /// (<see cref="ILocalKeys.FindAnchoredKeys"/>), or the ones of a remote with the signer's full name. When the signer
    /// is unknown with the keys held (it rotated since), the events of the statement are applied first (they must verify
    /// from the anchor or from the keys held) and the signature is checked again.
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="verifier">The keys of the local party that verifies.</param>
    /// <param name="purpose">The expected purpose.</param>
    /// <returns>The verdict: <see cref="SignatureVerdict.Refused"/> when the signer's keys are not known here.</returns>
    public SignatureVerdict Verify( IActivityLineEmitter logger, ILocalKeys verifier, string purpose )
    {
        Throw.CheckNotNullArgument( verifier );
        if( purpose != Purpose )
        {
            logger.Warn( $"A statement of '{SignerFullName}' for '{Purpose}' is refused: '{purpose}' is expected." );
            return SignatureVerdict.Refused;
        }
        var keys = verifier.FindAnchoredKeys( SignerFullName )
                   ?? (verifier.Party as ILocalParty)?.Remotes.FirstOrDefault( r => r.FullName.Path == SignerFullName )?.GetFeature<IRemoteKeys>() as IAnchoredKeys;
        if( keys == null )
        {
            logger.Warn( $"A statement of '{SignerFullName}' is refused: '{verifier.Party}' doesn't know its keys (no trust anchor, not a remote)." );
            return SignatureVerdict.Refused;
        }
        var verdict = keys.Check( logger, Purpose, _data, Signature );
        if( verdict == SignatureVerdict.UnknownIssuer && _events.Length > 0 )
        {
            keys.ApplyEvents( logger, _events );
            verdict = keys.Check( logger, Purpose, _data, Signature );
        }
        return verdict;
    }

    /// <summary>
    /// Encodes the statement: a version byte, then (big-endian lengths on 4 bytes) the signer's full name and the purpose
    /// (UTF-8), the data, the count of events and each event, the signature.
    /// </summary>
    /// <returns>The bytes.</returns>
    public byte[] Encode()
    {
        var m = new MemoryStream();
        m.WriteByte( Version );
        WriteBytes( m, Encoding.UTF8.GetBytes( SignerFullName ) );
        WriteBytes( m, Encoding.UTF8.GetBytes( Purpose ) );
        WriteBytes( m, _data );
        WriteInt( m, _events.Length );
        foreach( var e in _events ) WriteBytes( m, e.Encoded.Span );
        WriteBytes( m, Signature.Encoded.Span );
        return m.ToArray();

        static void WriteInt( MemoryStream m, int v )
        {
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian( b, v );
            m.Write( b );
        }

        static void WriteBytes( MemoryStream m, ReadOnlySpan<byte> bytes )
        {
            WriteInt( m, bytes.Length );
            m.Write( bytes );
        }
    }

    /// <summary>
    /// Decodes a statement (says nothing of its validity: see <see cref="Verify"/>).
    /// </summary>
    /// <param name="encoded">The bytes.</param>
    /// <param name="statement">The statement, null when the bytes are malformed.</param>
    /// <returns>True when the bytes are well formed.</returns>
    public static bool TryDecode( ReadOnlySpan<byte> encoded, out AnchoredStatement? statement )
    {
        statement = null;
        try
        {
            if( encoded.Length == 0 || encoded.Length > MaxEncodedSize || encoded[0] != Version ) return false;
            int pos = 1;
            var signer = Encoding.UTF8.GetString( ReadBytes( encoded, ref pos, 3 * CoreApplicationIdentity.FullNameMaxLength ) );
            var purpose = Encoding.UTF8.GetString( ReadBytes( encoded, ref pos, ApplicationSignature.MaxPurposeLength ) );
            var data = ReadBytes( encoded, ref pos, MaxDataLength ).ToArray();
            int count = ReadInt( encoded, ref pos );
            if( count < 0 || count > KeyEventChain.MaxEventWindow || signer.Length == 0 || purpose.Length == 0 ) return false;
            var events = new KeyEvent[count];
            for( int i = 0; i < count; ++i )
            {
                events[i] = KeyEvent.Read( ReadBytes( encoded, ref pos, KeyEvent.MaxEncodedSize ) );
                if( i > 0 && events[i].Seq != events[i - 1].Seq + 1 ) return false;
            }
            if( !ApplicationSignature.TryRead( ReadBytes( encoded, ref pos, int.MaxValue ), out var signature ) || pos != encoded.Length ) return false;
            statement = new AnchoredStatement( signer, purpose, data, events, signature );
            return true;
        }
        catch( InvalidDataException )
        {
            return false;
        }

        static int ReadInt( ReadOnlySpan<byte> encoded, ref int pos )
        {
            if( pos + 4 > encoded.Length ) throw new InvalidDataException();
            var v = BinaryPrimitives.ReadInt32BigEndian( encoded.Slice( pos ) );
            pos += 4;
            return v;
        }

        static ReadOnlySpan<byte> ReadBytes( ReadOnlySpan<byte> encoded, ref int pos, int maxLength )
        {
            int len = ReadInt( encoded, ref pos );
            if( len < 0 || len > maxLength || pos + len > encoded.Length ) throw new InvalidDataException();
            var r = encoded.Slice( pos, len );
            pos += len;
            return r;
        }
    }

    /// <summary>
    /// Overridden to return the signer, the purpose and the expiration.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => $"Statement '{Purpose}' of '{SignerFullName}' (until {Expiration:O})";
}
