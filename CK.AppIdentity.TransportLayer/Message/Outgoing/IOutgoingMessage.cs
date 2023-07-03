using CK.Core;
using System.Buffers;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// An outgoing message is immutable. It is a <see cref="IRefCounted"/> object that can be disposed:
    ///<see cref="IDisposable.Dispose"/> is the same as calling <see cref="IRefCounted.Release"/>.
    /// Apart from the 4 static singletons defined here, instances can only be created
    /// by a <see cref="OutgoingMessageBuilder"/>.
    /// </summary>
    public interface IOutgoingMessage : IOutgoingMessageData, IRefCounted
    {
        /// <summary>
        /// A purely invalid message singleton. It can be safely disposed and will remain invalid.
        /// <see cref="Canceled"/> is also invalid but conveys a cancellation of the process.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly IOutgoingMessage Invalid = new StaticEmpty( 0 );

        /// <summary>
        /// A canceled message singleton is invalid. It can be safely disposed and will remain invalid.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly IOutgoingMessage Canceled = new StaticEmpty( 0 );

        /// <summary>
        /// The "0 Protocol" empty message singleton is a 0 byte prefixed message (2 bytes on the wire).
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly IOutgoingMessage Empty = new StaticEmpty( 1 );

        /// <summary>
        /// The "0 Protocol" empty acknowledgment message singleton (2 bytes on the wire) with
        /// a true <see cref="IOutgoingMessageData.IsControl"/>.
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly IOutgoingMessage EmptyAck = new StaticEmpty( 2 );

        sealed class StaticEmpty : IOutgoingMessage
        {
            int _ackOrEmptyAck;
            public StaticEmpty( int ackOrEmptyAck )
            {
                _ackOrEmptyAck = ackOrEmptyAck;
            }

            public MessageProtocol Protocol => MessageProtocol.ZeroProtocol;

            public object? Source => null;

            public bool IsValid => _ackOrEmptyAck != 0;

            public bool IsControl => _ackOrEmptyAck == 2;

            public bool IsData => _ackOrEmptyAck != 2;

            public ReadOnlySequence<byte> Message
            {
                get
                {
                    Throw.CheckState( IsValid );
                    return ReadOnlySequence<byte>.Empty;
                }
            }

            public void AddRef()
            {
            }

            public void Release()
            {
            }
        }

    }
}
