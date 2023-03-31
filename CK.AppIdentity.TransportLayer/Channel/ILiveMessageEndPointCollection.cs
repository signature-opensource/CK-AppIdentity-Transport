namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// The set of currently connected endpoints exposed by <see cref="TransportLayerFeature.LiveEndPoints"/>.
    /// This is a "live" set because the underlying transport of an endpoint can die at any time.
    /// <para>
    /// The count can change and a end point with a false <see cref="MessageEndPoint.IsConnected"/> can appear in the
    /// set or be returned by  <see cref="GetNext(MessageEndPoint?)"/>.
    /// </para>
    /// </summary>
    public interface ILiveMessageEndPointCollection : IReadOnlyCollection<MessageEndPoint>
    {
        /// <summary>
        /// Implements a round robin enumeration.
        /// </summary>
        /// <param name="previous">The previously obtained endpoint.</param>
        /// <returns>The next endpoint to consider. Null if no connected endpoint exist.</returns>
        MessageEndPoint? GetNext( MessageEndPoint? previous );
    }

}
