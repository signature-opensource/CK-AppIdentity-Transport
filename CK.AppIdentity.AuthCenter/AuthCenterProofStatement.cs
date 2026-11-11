using CK.Core;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The statement of the Authentication Center that a routed user's proof is valid (the answer to an
/// <c>IVerifyRoutedProofQCommand</c>): it signs (<see cref="Purpose"/>) the destination, the nonce of the asking party,
/// the digest of the token and of the seal. The asking party verifies it with the keys of the Authentication Center (its
/// trust anchor): the answer crosses hops, a hop can withhold it, not forge it.
/// </summary>
public static class AuthCenterProofStatement
{
    /// <summary>
    /// The purpose of the signature of a statement by the Authentication Center.
    /// </summary>
    public const string Purpose = "CK.AuthCenter.ProofStatement";

    /// <summary>
    /// The size of the nonce chosen by the asking party.
    /// </summary>
    public const int NonceSize = 16;

    /// <summary>
    /// The lifetime of a statement: 1 minute (it is checked at once by the asking party).
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes( 1 );

    /// <summary>
    /// Gets the data signed by a statement.
    /// </summary>
    /// <param name="destination">The full name of the asking party (the destination of the routed command).</param>
    /// <param name="nonce">The nonce chosen by the asking party.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="seal">The seal of the routed command.</param>
    /// <returns>The signed data.</returns>
    public static byte[] GetSignedData( string destination, ReadOnlySpan<byte> nonce, string token, RoutedProofSeal seal )
    {
        Throw.CheckNotNullOrEmptyArgument( destination );
        Throw.CheckNotNullArgument( token );
        Throw.CheckNotNullArgument( seal );
        var m = new MemoryStream();
        using( var w = new BinaryWriter( m, Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( destination );
            w.Write( (byte)nonce.Length );
            w.Write( nonce );
            w.Write( SHA256.HashData( Encoding.UTF8.GetBytes( token ) ) );
            w.Write( SHA256.HashData( seal.Header ) );
            w.Write( (byte)seal.PayloadDigest.Length );
            w.Write( seal.PayloadDigest );
        }
        return m.ToArray();
    }
}
