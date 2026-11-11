using CK.Core;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// A point of the key event log of a party: the sequence of an event and its digest (<see cref="KeyEvent.GetDigest"/>,
/// that covers the full name of the party). Its text form is <c>{seq}:{digest}</c>, the digest in lowercase hex.
/// <para>
/// A checkpoint names the identity of a party from this event on: every event commits to the previous one and the next
/// key is committed in advance, so the events after the checkpoint are verified from it. A trust anchor
/// (<c>Local:TrustAnchors:{FullName}</c>, see <see cref="ILocalKeys.TrustAnchors"/>) is a checkpoint given by the
/// configuration: the inception (sequence 0) or a later event.
/// </para>
/// </summary>
public sealed class KeyCheckpoint : IEquatable<KeyCheckpoint>
{
    /// <summary>
    /// The length of a digest (SHA-256).
    /// </summary>
    public const int DigestLength = 32;

    readonly byte[] _digest;

    KeyCheckpoint( int seq, byte[] digest )
    {
        Seq = seq;
        _digest = digest;
    }

    /// <summary>
    /// Gets the checkpoint of an event of the log of a party.
    /// </summary>
    /// <param name="fullName">The full name of the party.</param>
    /// <param name="e">The event.</param>
    /// <returns>The checkpoint.</returns>
    public static KeyCheckpoint Of( string fullName, KeyEvent e )
    {
        Throw.CheckNotNullOrEmptyArgument( fullName );
        Throw.CheckNotNullArgument( e );
        return new KeyCheckpoint( e.Seq, e.GetDigest( fullName ).ToArray() );
    }

    /// <summary>
    /// Gets the sequence of the event.
    /// </summary>
    public int Seq { get; }

    /// <summary>
    /// Gets the digest of the event (<see cref="DigestLength"/> bytes).
    /// </summary>
    public ReadOnlySpan<byte> Digest => _digest;

    /// <summary>
    /// Gets whether an event of the log of a party is the one this checkpoint names.
    /// </summary>
    /// <param name="fullName">The full name of the party.</param>
    /// <param name="e">The event.</param>
    /// <returns>True when the event has the sequence and the digest of this checkpoint.</returns>
    public bool Matches( string fullName, KeyEvent e )
    {
        Throw.CheckNotNullOrEmptyArgument( fullName );
        Throw.CheckNotNullArgument( e );
        return e.Seq == Seq && e.GetDigest( fullName ).Span.SequenceEqual( _digest );
    }

    /// <summary>
    /// Parses the text form <c>{seq}:{digest}</c> (see <see cref="ToString"/>). The hex digest is case insensitive.
    /// </summary>
    /// <param name="s">The text.</param>
    /// <param name="checkpoint">The checkpoint on success.</param>
    /// <param name="error">The error on failure.</param>
    /// <returns>True on success, false otherwise.</returns>
    public static bool TryParse( string? s, [NotNullWhen( true )] out KeyCheckpoint? checkpoint, [NotNullWhen( false )] out string? error )
    {
        checkpoint = null;
        var t = s?.Trim();
        int sep = t?.IndexOf( ':' ) ?? -1;
        if( t == null || sep <= 0 )
        {
            error = $"Invalid key checkpoint '{s}': '{{seq}}:{{digest}}' is expected.";
            return false;
        }
        if( !int.TryParse( t.AsSpan( 0, sep ), NumberStyles.None, CultureInfo.InvariantCulture, out var seq ) )
        {
            error = $"Invalid key checkpoint '{s}': its sequence is not a positive integer.";
            return false;
        }
        var hex = t.AsSpan( sep + 1 );
        if( hex.Length != 2 * DigestLength )
        {
            error = $"Invalid key checkpoint '{s}': its digest must be {2 * DigestLength} hexadecimal characters.";
            return false;
        }
        byte[] digest;
        try
        {
            digest = Convert.FromHexString( hex );
        }
        catch( FormatException )
        {
            error = $"Invalid key checkpoint '{s}': its digest is not hexadecimal.";
            return false;
        }
        checkpoint = new KeyCheckpoint( seq, digest );
        error = null;
        return true;
    }

    /// <inheritdoc />
    public bool Equals( KeyCheckpoint? other ) => other != null && other.Seq == Seq && other._digest.AsSpan().SequenceEqual( _digest );

    /// <inheritdoc />
    public override bool Equals( object? obj ) => Equals( obj as KeyCheckpoint );

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine( Seq, BitConverter.ToInt32( _digest, 0 ) );

    /// <summary>
    /// Returns <c>{seq}:{digest}</c>, the digest in lowercase hex.
    /// </summary>
    /// <returns>The text form.</returns>
    public override string ToString() => $"{Seq}:{Convert.ToHexStringLower( _digest )}";
}
