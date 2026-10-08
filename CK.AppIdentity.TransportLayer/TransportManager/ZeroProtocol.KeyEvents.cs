using CK.AppIdentity.KeyManagement;
using CK.Core;

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
    internal static IOutgoingMessage CreateKeyEventsMessage( LocalIdentityState state )
    {
        var builder = _zeroFactory.CreateBuilder();
        var sequence = builder.ObtainSequence();
        var w = new FastByteWriter( sequence );
        w.WriteByte( DRunKeyEvents );
        // Independent serialization version.
        w.WriteSmallUInt32( 0 );
        var tail = state.Tail;
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
    /// Creates the message that asks the peer for its last key events.
    /// </summary>
    /// <returns>The message.</returns>
    internal static IOutgoingMessage CreateKeyEventsRequestMessage()
    {
        var builder = _zeroFactory.CreateBuilder();
        var sequence = builder.ObtainSequence();
        var w = new FastByteWriter( sequence );
        w.WriteByte( DRunKeyEventsRequest );
        w.WriteSmallUInt32( 0 );
        w.Commit();
        return builder.CreateMessage( sequence );
    }

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
        Throw.CheckData( count >= 1 && count <= KeyEventChain.MaxEventTail );
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
