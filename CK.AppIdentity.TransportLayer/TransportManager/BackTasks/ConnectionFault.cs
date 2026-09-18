using System;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Tells a fault the peer caused from a fault we caused.
/// <para>
/// Every parse path can throw on hostile input, and catching that per connection is right. Logging it
/// as an <c>Error</c> with a full stack is not: on a public port, a malformed frame or a peer hanging
/// up mid-handshake is an ordinary event, not a defect in this code. Reported that way it costs a
/// stack trace per attempt — which an unauthenticated flood turns into a log-volume problem — and it
/// puts routine noise in the same bucket an operator watches for real faults, where it buries them.
/// </para>
/// <para>
/// So these are reported short and without a stack, and everything else keeps the loud treatment.
/// The aggregate view of a flood belongs to <see cref="NegotiationGate"/>'s counters, not to one line
/// per attempt.
/// </para>
/// </summary>
static class ConnectionFault
{
    /// <summary>
    /// Whether <paramref name="ex"/> is something a peer can cause by sending bad bytes or by going
    /// away, as opposed to something wrong on this side.
    /// </summary>
    /// <param name="ex">The fault, typically a faulted task's <see cref="AggregateException"/>.</param>
    /// <returns>True when nothing here needs investigating.</returns>
    internal static bool IsPeerFault( Exception? ex )
    {
        if( ex == null ) return false;
        if( ex is AggregateException agg )
        {
            var inner = agg.Flatten().InnerExceptions;
            if( inner.Count == 0 ) return false;
            // EVERY one must be a peer fault. A genuine bug travelling alongside a broken pipe is
            // exactly the case that must not be quietly downgraded.
            foreach( var e in inner )
            {
                if( !IsPeerFault( e ) ) return false;
            }
            return true;
        }
        // InvalidDataException is what Throw.CheckData and the parsers raise on malformed input.
        // IOException covers EndOfStreamException, which is a truncated message.
        // OperationCanceledException is our own negotiation timeout firing.
        return ex is System.IO.InvalidDataException
                  or System.IO.IOException
                  or System.Net.Sockets.SocketException
                  or OperationCanceledException;
    }

    /// <summary>
    /// A short name for the fault, for the one-line form.
    /// </summary>
    /// <param name="ex">The fault.</param>
    /// <returns>The base exception's type name.</returns>
    internal static string ShortName( Exception ex ) => ex.GetBaseException().GetType().Name;
}
