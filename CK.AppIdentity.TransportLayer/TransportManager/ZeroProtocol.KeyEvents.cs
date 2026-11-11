using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity.TransportLayer;

static partial class ZeroProtocol
{
    // Run discriminators of the key events (R1): a party pushes its last key events to its connected remotes right
    // after a rotation (and answers a request for them), so that they move their pin without waiting for a handshake.
    // An older peer logs a warning and ignores them.
    internal const byte DRunKeyEvents = 254;
    internal const byte DRunKeyEventsRequest = 253;

    /// <summary>
    /// Creates the message that carries the last key events of a party (its <see cref="LocalIdentityState.Tail"/>).
    /// It needs no signature: the run-phase frames are authenticated as coming from the session peer and the events
    /// prove themselves (they can only move the pin forward along the legitimate chain).
    /// </summary>
    /// <param name="state">The identity state.</param>
    /// <returns>The message.</returns>
    internal static IOutgoingMessage CreateKeyEventsMessage( LocalIdentityState state, int? heldSeq )
    {
        var builder = _zeroFactory.CreateBuilder();
        var sequence = builder.ObtainSequence();
        var w = new FastByteWriter( sequence );
        w.WriteByte( DRunKeyEvents );
        // Independent serialization version.
        w.WriteSmallUInt32( 0 );
        var tail = GetEventsFrom( state, heldSeq );
        w.WriteSmallUInt32( (uint)tail.Count );
        foreach( var e in tail )
        {
            w.WriteSmallUInt32( (uint)e.Encoded.Length );
            w.WriteBytes( e.Encoded.Span );
        }
        w.Commit();
        return builder.CreateMessage( sequence );
    }

    /// <summary>
    /// Creates the message that asks the peer for its key events, from the point of its log that we hold (our pin or our
    /// anchor of it): the peer sends its events from there (up to <see cref="KeyEventChain.MaxEventWindow"/>).
    /// </summary>
    /// <param name="stated">What we hold of the peer's log, null if nothing.</param>
    /// <returns>The message.</returns>
    internal static IOutgoingMessage CreateKeyEventsRequestMessage( KeyCheckpoint? stated )
    {
        var builder = _zeroFactory.CreateBuilder();
        var sequence = builder.ObtainSequence();
        var w = new FastByteWriter( sequence );
        w.WriteByte( DRunKeyEventsRequest );
        w.WriteSmallUInt32( 0 );
        w.WriteSmallUInt32( stated == null ? 0 : (uint)stated.Seq + 1 );
        w.Commit();
        return builder.CreateMessage( sequence );
    }

    /// <summary>
    /// Reads the point of our log that the peer holds, from a <see cref="DRunKeyEventsRequest"/> message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <returns>The sequence the peer holds, null if nothing.</returns>
    internal static int? ReadKeyEventsRequest( IncomingMessage message )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DRunKeyEventsRequest );
        Throw.CheckData( r.ReadSmallUInt32() == 0 ); // Version.
        var held = r.ReadSmallUInt32();
        return held == 0 ? null : (int)(held - 1);
    }

    // See LocalIdentityState.GetEventsFrom.
    internal static IReadOnlyList<KeyEvent> GetEventsFrom( LocalIdentityState state, int? heldSeq ) => state.GetEventsFrom( heldSeq );

    /// <summary>
    /// Reads the key events of a <see cref="DRunKeyEvents"/> message.
    /// Throws an <see cref="System.IO.InvalidDataException"/> on malformed data.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <returns>The key events, oldest first.</returns>
    internal static KeyEvent[] ReadKeyEvents( IncomingMessage message )
    {
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DRunKeyEvents );
        Throw.CheckData( r.ReadSmallUInt32() == 0 ); // Version.
        var count = r.ReadSmallUInt32();
        Throw.CheckData( count >= 1 && count <= KeyEventChain.MaxEventWindow );
        var tail = new KeyEvent[count];
        for( int i = 0; i < tail.Length; ++i )
        {
            var len = r.ReadSmallUInt32();
            Throw.CheckData( len > 0 && len <= KeyEvent.MaxEncodedSize );
            tail[i] = KeyEvent.Read( r.ReadBytes( len ) );
        }
        return tail;
    }
}
