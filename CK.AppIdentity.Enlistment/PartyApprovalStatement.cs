using CK.IO.AppIdentity.Enlistment;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace CK.AppIdentity.Enlistment;

/// <summary>
/// The signature of an <see cref="IPartyApprovalStatement"/> by the host of the approval page (<see cref="Purpose"/>): it
/// covers every field of the statement but its signatures.
/// </summary>
public static class PartyApprovalStatement
{
    /// <summary>
    /// The purpose of the signature of a statement by the host of the approval page.
    /// </summary>
    public const string Purpose = "CK.AppIdentity.PartyApproval";

    /// <summary>
    /// The lifetime of the signature of a statement: the approval must reach its holder within it, and a replay is bounded
    /// by it.
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes( 10 );

    /// <summary>
    /// Gets the data signed by a statement: its party, key fingerprint, holder and host (each one: its UTF-8 length on 4
    /// bytes, then its UTF-8 bytes), the operator's actor identifier (4 bytes), the ticks of its time (8 bytes), then the
    /// count of its routes (4 bytes) and each route like the strings above, big-endian.
    /// </summary>
    /// <param name="statement">The statement.</param>
    /// <returns>The signed data.</returns>
    public static byte[] GetSignedData( IPartyApprovalStatement statement )
    {
        var m = new MemoryStream();
        var b = new byte[8];
        void Write( string s )
        {
            var bytes = Encoding.UTF8.GetBytes( s );
            BinaryPrimitives.WriteInt32BigEndian( b, bytes.Length );
            m.Write( b, 0, 4 );
            m.Write( bytes );
        }
        Write( statement.PartyFullName );
        Write( statement.KeyFingerprint );
        Write( statement.HolderFullName );
        Write( statement.HostFullName );
        BinaryPrimitives.WriteInt32BigEndian( b, statement.OperatorActorId );
        m.Write( b, 0, 4 );
        BinaryPrimitives.WriteInt64BigEndian( b, statement.Time.Ticks );
        m.Write( b );
        BinaryPrimitives.WriteInt32BigEndian( b, statement.Routes.Count );
        m.Write( b, 0, 4 );
        foreach( var r in statement.Routes ) Write( r );
        return m.ToArray();
    }
}
