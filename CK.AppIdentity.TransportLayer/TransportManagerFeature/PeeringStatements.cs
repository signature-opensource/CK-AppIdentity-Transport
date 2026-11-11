using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Optional service: the authority of the System of a local party (its Authentication Center, implemented by
/// CK.AppIdentity.AuthCenter.Enlistment), whose statements (<see cref="AnchoredStatement"/>) make the peering of a party
/// that is connected to nothing safer:
/// <list type="bullet">
///   <item>the <see cref="EnlistmentUrlStatement"/>: the approval page of the System, authenticated for the party that
///   receives it (<see cref="PeeringIssue.IsEnlistUrlAuthenticated"/>);</item>
///   <item>the <see cref="PinGrant"/>: the approval of a party, made on the approval page, also approves the party that
///   holds its pending approval for it (a "both approval" in one gesture).</item>
/// </list>
/// A statement is verified with the keys of the authority as the local party holds them: its trust anchor (or its pin
/// when it is a remote). Without this service, or without an authority, the peering is unchanged.
/// </summary>
public interface IPeeringAuthority : ISingletonAutoService
{
    /// <summary>
    /// Gets the full name of the party whose statements a local party accepts, null when it has none.
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <returns>The full name of the authority, or null.</returns>
    string? GetAuthority( ILocalParty local );

    /// <summary>
    /// Gets the current <see cref="EnlistmentUrlStatement"/> of the System of a local party, null when none is known.
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <returns>The statement, or null.</returns>
    AnchoredStatement? GetEnlistmentUrl( ILocalParty local );
}

/// <summary>
/// The statement "the approval page of this System is U", signed by the authority of the System
/// (<see cref="IPeeringAuthority"/>). U is the target of the "Enlistment" route as the authority sees it
/// (<see cref="TransportFeatureDriver.EnlistmentRouteName"/>): the party that receives it appends <c>?party={its full name}</c>.
/// </summary>
public static class EnlistmentUrlStatement
{
    /// <summary>
    /// The purpose of the signature.
    /// </summary>
    public const string Purpose = "CK.AppIdentity.EnlistmentUrl";

    /// <summary>
    /// The maximal length of the URL, in UTF-8 bytes (it travels in the negotiation messages).
    /// </summary>
    public const int MaxUrlLength = ZeroProtocol.MaxEnlistRemoteUrlLength;

    /// <summary>
    /// The lifetime of a statement: 3 days, at most the <see cref="ILocalKeys.MaxSignatureDays"/> of the authority (it
    /// signs it again at half-life).
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays( 3 );

    /// <summary>
    /// Signs the statement.
    /// </summary>
    /// <param name="authority">The keys of the authority.</param>
    /// <param name="url">The URL of the approval page (at most <see cref="MaxUrlLength"/> UTF-8 bytes).</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The statement.</returns>
    public static AnchoredStatement Create( ILocalKeys authority, string url, DateTime utcNow )
    {
        Throw.CheckNotNullOrEmptyArgument( url );
        var data = Encoding.UTF8.GetBytes( url );
        Throw.CheckArgument( data.Length <= MaxUrlLength );
        return AnchoredStatement.Create( authority, Purpose, data, utcNow + Bound( Lifetime, authority ) );
    }

    // A lifetime bounded by the signatures the authority may make (ILocalKeys.MaxSignatureDays).
    internal static TimeSpan Bound( TimeSpan lifetime, ILocalKeys authority )
    {
        var max = TimeSpan.FromDays( authority.MaxSignatureDays );
        return lifetime < max ? lifetime : max;
    }

    /// <summary>
    /// Reads the URL of a statement (says nothing of its validity).
    /// </summary>
    /// <param name="statement">The statement.</param>
    /// <returns>The URL, or null when this is not an enlistment URL statement.</returns>
    public static string? TryRead( AnchoredStatement statement )
    {
        if( statement.Purpose != Purpose
            || statement.Data.Length == 0
            || statement.Data.Length > MaxUrlLength )
        {
            return null;
        }
        return Encoding.UTF8.GetString( statement.Data.Span );
    }
}

/// <summary>
/// The statement "the waiting party W, whose key is F, may pin the holder H from the checkpoint C", signed by the authority
/// of the System (<see cref="IPeeringAuthority"/>) when an operator approves W on the approval page and H holds the pending
/// approval of W: H hands it over to W at its next attempt (H being connected or not to W, W being connected to nothing
/// else). C is what the authority itself knows of H (its pin, or its anchor), never what the page says.
/// <para>
/// A replay is harmless: it names W's key and H's log, only H can use it.
/// </para>
/// </summary>
public static class PinGrant
{
    /// <summary>
    /// The purpose of the signature.
    /// </summary>
    public const string Purpose = "CK.AppIdentity.PinGrant";

    /// <summary>
    /// The lifetime of a grant: 3 days, at most the <see cref="ILocalKeys.MaxSignatureDays"/> of the authority.
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays( 3 );

    /// <summary>
    /// Signs a grant.
    /// </summary>
    /// <param name="authority">The keys of the authority.</param>
    /// <param name="waitingFullName">The full name of the waiting party W.</param>
    /// <param name="waitingKeyFingerprint">The fingerprint of the identity key of W.</param>
    /// <param name="holderFullName">The full name of the holder H.</param>
    /// <param name="holder">The checkpoint of H's key event log.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The grant.</returns>
    public static AnchoredStatement Create( ILocalKeys authority,
                                            string waitingFullName,
                                            string waitingKeyFingerprint,
                                            string holderFullName,
                                            KeyCheckpoint holder,
                                            DateTime utcNow )
    {
        Throw.CheckNotNullOrEmptyArgument( waitingFullName );
        Throw.CheckNotNullOrEmptyArgument( waitingKeyFingerprint );
        Throw.CheckNotNullOrEmptyArgument( holderFullName );
        Throw.CheckNotNullArgument( holder );
        var m = new MemoryStream();
        Write( m, waitingFullName );
        Write( m, waitingKeyFingerprint );
        Write( m, holderFullName );
        Write( m, holder.ToString() );
        return AnchoredStatement.Create( authority, Purpose, m.ToArray(), utcNow + EnlistmentUrlStatement.Bound( Lifetime, authority ) );

        static void Write( MemoryStream m, string s )
        {
            var bytes = Encoding.UTF8.GetBytes( s );
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian( b, bytes.Length );
            m.Write( b );
            m.Write( bytes );
        }
    }

    /// <summary>
    /// Reads a grant (says nothing of its validity).
    /// </summary>
    /// <param name="statement">The statement.</param>
    /// <param name="waitingFullName">The full name of the waiting party W.</param>
    /// <param name="waitingKeyFingerprint">The fingerprint of the identity key of W.</param>
    /// <param name="holderFullName">The full name of the holder H.</param>
    /// <param name="holder">The checkpoint of H's key event log.</param>
    /// <returns>True when this is a well-formed grant.</returns>
    public static bool TryRead( AnchoredStatement statement,
                                out string waitingFullName,
                                out string waitingKeyFingerprint,
                                out string holderFullName,
                                out KeyCheckpoint? holder )
    {
        waitingFullName = waitingKeyFingerprint = holderFullName = string.Empty;
        holder = null;
        if( statement.Purpose != Purpose ) return false;
        var data = statement.Data.Span;
        int pos = 0;
        if( !Read( data, ref pos, out waitingFullName )
            || !Read( data, ref pos, out waitingKeyFingerprint )
            || !Read( data, ref pos, out holderFullName )
            || !Read( data, ref pos, out var checkpoint )
            || pos != data.Length
            || waitingFullName.Length == 0
            || waitingKeyFingerprint.Length == 0
            || holderFullName.Length == 0 )
        {
            return false;
        }
        return KeyCheckpoint.TryParse( checkpoint, out holder, out _ );

        static bool Read( ReadOnlySpan<byte> data, ref int pos, out string s )
        {
            s = string.Empty;
            if( pos + 4 > data.Length ) return false;
            int len = BinaryPrimitives.ReadInt32BigEndian( data.Slice( pos ) );
            pos += 4;
            if( len < 0 || pos + len > data.Length ) return false;
            s = Encoding.UTF8.GetString( data.Slice( pos, len ) );
            pos += len;
            return true;
        }
    }
}
