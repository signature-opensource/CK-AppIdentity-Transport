//using System.Buffers;

//namespace CK.AppIdentity.TransportLayer
//{


//    /// <summary>
//    /// Read only view of a <see cref="TransportMessage"/> that can be retained or disposed.
//    /// <para>
//    /// This doesn't extend <see cref="IDisposable"/> and this is intended.
//    /// </para>
//    /// </summary>
//    public interface ITransportMessage : ITransportMessageData
//    {
//        /// <summary>
//        /// Retains this message, preventing a <see cref="Dispose()"/> to release the resources.
//        /// Dispose must be called as many times as Retain has been called for the resources to be released.
//        /// Calling this on the special messages <see cref="TransportMessage.Invalid"/>, <see cref="TransportMessage.Canceled"/>,
//        /// <see cref="TransportMessage.Empty"/> and <see cref="TransportMessage.EmptyAck"/>
//        /// or a static message (see <see cref="OutgoingMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/> )
//        /// has no effect and returns false.
//        /// </summary>
//        /// <returns>
//        /// True if the message has been retained and <see cref="Dispose()"/> must be called.
//        /// False if it is already Disposed, if this is one of the special messages or is a static message.
//        /// </returns>
//        bool Retain();

//        /// <summary>
//        /// Disposes this message.
//        /// The <see cref="TransportMessage.Invalid"/>, <see cref="TransportMessage.Canceled"/>, <see cref="TransportMessage.Empty"/>
//        /// and <see cref="TransportMessage.EmptyAck"/> messages ignore this,
//        /// as well as messages created by the static <see cref="OutgoingMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/>
//        /// method.
//        /// </summary>
//        void Dispose();
//    }
//}
