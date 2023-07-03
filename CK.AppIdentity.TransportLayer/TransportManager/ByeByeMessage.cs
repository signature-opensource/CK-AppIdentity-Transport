namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Bye-bye message has a text reason and a number of seconds that the other part
    /// should honor by waiting at least this time before trying to reconnect.
    /// <para>
    /// The <paramref name="ShutUp"/> applies to connection initiator. Listeners ignore it. 
    /// </para>
    /// </summary>
    /// <param name="Reason">Reason of the disconnection.</param>
    /// <param name="ShutUp">Time to wait before reconnecting.</param>
    public sealed record ByeByeMessage( string Reason, TimeSpan ShutUp )
    {
        public override string ToString() => $"{Reason} (Shut up: {ShutUp})";
    }
}
