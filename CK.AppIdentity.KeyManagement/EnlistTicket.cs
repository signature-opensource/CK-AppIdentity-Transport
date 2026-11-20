using CK.Core;
using System;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// A pre-authorized enlistment ticket: an operator opens it on the approval page of the System (or with
/// <c>ckey ticket open</c> on the Authentication Center) for an expected party, and the party starts with it
/// ("Local:KeyManagement:EnlistTicket", a secret). It is a one-time P-256 signing key: the center keeps only its public
/// key, the party proves it holds the ticket in its initial message (<see cref="SignProof"/>) and the center trusts its
/// key at once, without an approval code. The ticket also carries the trust anchor of the center: the party verifies the
/// center from it on its first connection (and pins it).
/// <para>
/// Its text (<see cref="Encode"/>) is "ckt1." followed by the base64url of: a version byte, the 16 bytes of the
/// <see cref="Id"/>, the PKCS#8 private key, the full name and the checkpoint of the center, the expiration.
/// </para>
/// </summary>
public sealed class EnlistTicket : IDisposable
{
    /// <summary>
    /// The prefix of the text of a ticket.
    /// </summary>
    public const string Prefix = "ckt1.";

    /// <summary>
    /// The length of an <see cref="Id"/>.
    /// </summary>
    public const int IdLength = 16;

    /// <summary>
    /// The length of a proof signature (P-256, IEEE P1363: r || s).
    /// </summary>
    public const int SignatureLength = 64;

    /// <summary>
    /// The maximal length of an encoded proof: its id and its signature.
    /// </summary>
    public const int ProofLength = IdLength + SignatureLength;

    const byte _version = 1;
    static readonly byte[] _proofLabel = Encoding.ASCII.GetBytes( "CK.AppIdentity.EnlistTicket" );

    readonly ECDsa _key;

    EnlistTicket( byte[] id, ECDsa key, string centerFullName, KeyCheckpoint centerCheckpoint, DateTime expires )
    {
        Id = id;
        _key = key;
        CenterFullName = centerFullName;
        CenterCheckpoint = centerCheckpoint;
        Expires = expires;
    }

    /// <summary>
    /// Gets the identifier of the ticket (16 random bytes).
    /// </summary>
    public byte[] Id { get; }

    /// <summary>
    /// Gets the identifier as text (lowercase hexadecimal).
    /// </summary>
    public string IdText => Convert.ToHexStringLower( Id );

    /// <summary>
    /// Gets the full name of the Authentication Center that holds the ticket.
    /// </summary>
    public string CenterFullName { get; }

    /// <summary>
    /// Gets the trust anchor of the center: its checkpoint when the ticket was opened.
    /// </summary>
    public KeyCheckpoint CenterCheckpoint { get; }

    /// <summary>
    /// Gets the expiration of the ticket (UTC).
    /// </summary>
    public DateTime Expires { get; }

    /// <summary>
    /// Creates a new ticket.
    /// </summary>
    /// <param name="centerFullName">The full name of the center that holds it.</param>
    /// <param name="centerCheckpoint">The current checkpoint of the center.</param>
    /// <param name="expires">The expiration (UTC).</param>
    /// <param name="publicKey">The public key (SubjectPublicKeyInfo) that the center keeps.</param>
    /// <returns>The ticket: dispose it once encoded.</returns>
    public static EnlistTicket Create( string centerFullName, KeyCheckpoint centerCheckpoint, DateTime expires, out byte[] publicKey )
    {
        Throw.CheckNotNullOrEmptyArgument( centerFullName );
        Throw.CheckNotNullArgument( centerCheckpoint );
        Throw.CheckArgument( expires.Kind == DateTimeKind.Utc );
        var key = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        publicKey = key.ExportSubjectPublicKeyInfo();
        return new EnlistTicket( RandomNumberGenerator.GetBytes( IdLength ), key, centerFullName, centerCheckpoint, expires );
    }

    /// <summary>
    /// Creates the key of a new ticket: its id and its P-256 key, before the checkpoint of the center is known (the
    /// page's host registers the public key on the center, that answers its checkpoint). See
    /// <see cref="Create(byte[], ECDsa, string, KeyCheckpoint, DateTime)"/>.
    /// </summary>
    /// <param name="id">The new id.</param>
    /// <returns>The new key.</returns>
    public static ECDsa CreateKey( out byte[] id )
    {
        id = RandomNumberGenerator.GetBytes( IdLength );
        return ECDsa.Create( ECCurve.NamedCurves.nistP256 );
    }

    /// <summary>
    /// Creates a ticket from a key created by <see cref="CreateKey"/>.
    /// </summary>
    /// <param name="id">The id.</param>
    /// <param name="key">The key: the ticket owns it.</param>
    /// <param name="centerFullName">The full name of the center that holds it.</param>
    /// <param name="centerCheckpoint">The current checkpoint of the center.</param>
    /// <param name="expires">The expiration (UTC).</param>
    /// <returns>The ticket: dispose it once encoded.</returns>
    public static EnlistTicket Create( byte[] id, ECDsa key, string centerFullName, KeyCheckpoint centerCheckpoint, DateTime expires )
    {
        Throw.CheckArgument( id != null && id.Length == IdLength );
        Throw.CheckArgument( key != null && key.KeySize == 256 );
        Throw.CheckNotNullOrEmptyArgument( centerFullName );
        Throw.CheckNotNullArgument( centerCheckpoint );
        Throw.CheckArgument( expires.Kind == DateTimeKind.Utc );
        return new EnlistTicket( id, key, centerFullName, centerCheckpoint, expires );
    }

    /// <summary>
    /// Encodes the ticket: the text that the party is given (a secret).
    /// </summary>
    /// <returns>The text.</returns>
    public string Encode()
    {
        using var s = new MemoryStream();
        using( var w = new BinaryWriter( s, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( _version );
            w.Write( Id );
            var pkcs8 = _key.ExportPkcs8PrivateKey();
            w.Write( (ushort)pkcs8.Length );
            w.Write( pkcs8 );
            w.Write( CenterFullName );
            w.Write( CenterCheckpoint.ToString() );
            w.Write( Expires.Ticks );
        }
        return Prefix + Base64Url.EncodeToString( s.ToArray() );
    }

    /// <summary>
    /// Reads the text of a ticket.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="ticket">The ticket on success: dispose it.</param>
    /// <param name="error">The error otherwise.</param>
    /// <returns>True on success.</returns>
    public static bool TryParse( string? text, [NotNullWhen( true )] out EnlistTicket? ticket, [NotNullWhen( false )] out string? error )
    {
        ticket = null;
        if( text == null || !text.StartsWith( Prefix, StringComparison.Ordinal ) )
        {
            error = $"A ticket starts with \"{Prefix}\".";
            return false;
        }
        ECDsa? key = null;
        try
        {
            var bytes = Base64Url.DecodeFromChars( text.AsSpan( Prefix.Length ) );
            using var r = new BinaryReader( new MemoryStream( bytes ), Encoding.UTF8 );
            if( r.ReadByte() != _version )
            {
                error = "Unknown ticket version.";
                return false;
            }
            var id = r.ReadBytes( IdLength );
            var pkcs8 = r.ReadBytes( r.ReadUInt16() );
            key = ECDsa.Create();
            key.ImportPkcs8PrivateKey( pkcs8, out _ );
            if( key.KeySize != 256 )
            {
                error = "The key of a ticket is a P-256 key.";
                return false;
            }
            var centerFullName = r.ReadString();
            if( !KeyCheckpoint.TryParse( r.ReadString(), out var checkpoint, out var checkpointError ) )
            {
                error = $"Invalid checkpoint of the center: {checkpointError}";
                return false;
            }
            var expires = new DateTime( r.ReadInt64(), DateTimeKind.Utc );
            if( id.Length != IdLength || r.BaseStream.Position != bytes.Length )
            {
                error = "Invalid ticket.";
                return false;
            }
            ticket = new EnlistTicket( id, key, centerFullName, checkpoint, expires );
            key = null;
            error = null;
            return true;
        }
        catch( Exception ex ) when( ex is FormatException or EndOfStreamException or CryptographicException or ArgumentException )
        {
            error = "Invalid ticket.";
            return false;
        }
        finally
        {
            key?.Dispose();
        }
    }

    /// <summary>
    /// Signs the proof of this ticket for a connection: the party (its full name and the checkpoint of its identity), the
    /// holder (the full name of the center) and the connection (its ephemeral public key) are signed: the proof can't be
    /// replayed for another key, another holder or another connection.
    /// </summary>
    /// <param name="fullName">The full name of the party.</param>
    /// <param name="identity">The checkpoint of the head of its key event log.</param>
    /// <param name="holderFullName">The full name of the holder.</param>
    /// <param name="ephemeralPublicKey">The ephemeral public key of the connection.</param>
    /// <returns>The proof: the <see cref="Id"/> then the signature (<see cref="ProofLength"/> bytes).</returns>
    public byte[] SignProof( string fullName, KeyCheckpoint identity, string holderFullName, ReadOnlySpan<byte> ephemeralPublicKey )
    {
        var data = GetProofData( fullName, identity, holderFullName, ephemeralPublicKey );
        var signature = _key.SignData( data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
        Throw.DebugAssert( signature.Length == SignatureLength );
        var proof = new byte[ProofLength];
        Id.CopyTo( proof, 0 );
        signature.CopyTo( proof, IdLength );
        return proof;
    }

    /// <summary>
    /// Gets the id of a proof (see <see cref="SignProof"/>).
    /// </summary>
    /// <param name="proof">The proof.</param>
    /// <returns>Its ticket id, as text.</returns>
    public static string GetProofId( ReadOnlySpan<byte> proof )
    {
        Throw.CheckArgument( proof.Length == ProofLength );
        return Convert.ToHexStringLower( proof.Slice( 0, IdLength ) );
    }

    /// <summary>
    /// Verifies a proof (see <see cref="SignProof"/>) with the public key of the ticket.
    /// </summary>
    /// <param name="publicKey">The public key of the ticket (SubjectPublicKeyInfo).</param>
    /// <param name="proof">The proof.</param>
    /// <param name="fullName">The full name of the party.</param>
    /// <param name="identity">The checkpoint of the head of its key event log.</param>
    /// <param name="holderFullName">The full name of the holder.</param>
    /// <param name="ephemeralPublicKey">The ephemeral public key of the connection.</param>
    /// <returns>True when the proof is valid.</returns>
    public static bool VerifyProof( ReadOnlySpan<byte> publicKey,
                                    ReadOnlySpan<byte> proof,
                                    string fullName,
                                    KeyCheckpoint identity,
                                    string holderFullName,
                                    ReadOnlySpan<byte> ephemeralPublicKey )
    {
        if( proof.Length != ProofLength ) return false;
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo( publicKey, out _ );
            var data = GetProofData( fullName, identity, holderFullName, ephemeralPublicKey );
            return key.VerifyData( data, proof.Slice( IdLength ), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
        }
        catch( CryptographicException )
        {
            return false;
        }
    }

    static byte[] GetProofData( string fullName, KeyCheckpoint identity, string holderFullName, ReadOnlySpan<byte> ephemeralPublicKey )
    {
        using var s = new MemoryStream();
        s.Write( _proofLabel );
        WriteString( s, fullName );
        WriteString( s, identity.ToString() );
        WriteString( s, holderFullName );
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian( len, ephemeralPublicKey.Length );
        s.Write( len );
        s.Write( ephemeralPublicKey );
        return s.ToArray();

        static void WriteString( MemoryStream s, string v )
        {
            var b = Encoding.UTF8.GetBytes( v );
            Span<byte> len = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian( len, b.Length );
            s.Write( len );
            s.Write( b );
        }
    }

    /// <summary>
    /// Disposes the key of the ticket.
    /// </summary>
    public void Dispose() => _key.Dispose();
}
