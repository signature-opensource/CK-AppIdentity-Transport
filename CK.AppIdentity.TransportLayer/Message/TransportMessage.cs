namespace CK.AppIdentity.TransportLayer
{
    public static class TransportMessage
    {
        /// <summary>
        /// A purely invalid message singleton. It can be safely disposed and will remain invalid.
        /// <see cref="Canceled"/> is also invalid but conveys a cancellation of the process.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly IIncomingMessage Invalid = new TransportMessageImpl( 0 );

        /// <summary>
        /// A canceled message singleton is invalid. It can be safely disposed and will remain invalid.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly IIncomingMessage Canceled = new TransportMessageImpl( 0 );

        /// <summary>
        /// The "0 Protocol" empty message singleton is a 0 byte prefixed message (2 bytes on the wire).
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly IIncomingMessage Empty = new TransportMessageImpl( 1 );

        /// <summary>
        /// The "0 Protocol" empty acknowledgment message singleton (2 bytes on the wire) with
        /// <see cref="TransportMessageImpl.IsResponse"/> set.
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly IIncomingMessage EmptyAck = new TransportMessageImpl( 2 );
    }
}
