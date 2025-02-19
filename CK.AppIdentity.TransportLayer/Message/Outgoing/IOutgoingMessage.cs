using CK.Core;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// An outgoing message is immutable. It is a <see cref="IRefCounted"/> object that can be disposed:
///<see cref="IDisposable.Dispose"/> is the same as calling <see cref="IRefCounted.Release"/>.
/// Apart from the 4 static singletons defined here, instances can only be created
/// by a <see cref="OutgoingMessageBuilder"/>.
/// </summary>
public interface IOutgoingMessage : IOutgoingMessageData, IRefCounted, IDisposable
{
    /// <summary>
    /// The prefix length on the wire is between 1 (for empty messages) and 5 bytes.
    /// </summary>
    public const int MaxWirePrefixLength = 5;

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


    /// <summary>
    /// Writes the wire header of a message according to a negotiated <see cref="MessageProtocolMap"/>.
    /// The <see cref="IOutgoingMessageData.Protocol"/> must be found in the negotiated protocols otherwise
    /// an <see cref="ArgumentException"/> is thrown.
    /// </summary>
    /// <param name="negociatedProtocols">The negociated protocol map.</param>
    /// <param name="message">The message (must be <see cref="IOutgoingMessageData.IsValid"/>).</param>
    /// <param name="header">Target buffer: must be least <see cref="MaxWirePrefixLength"/>.</param>
    /// <returns>The number of bytes written in the <paramref name="header"/>.</returns>
    public static int WriteWireHeader( MessageProtocolMap negociatedProtocols, IOutgoingMessage message, Span<byte> header )
    {
        Throw.CheckArgument( message.IsValid );
        Throw.CheckArgument( header.Length >= MaxWirePrefixLength );
        var protocolNumber = negociatedProtocols.GetProtocolIndex( message.Protocol );
        if( protocolNumber < 0 ) Throw.ArgumentException( nameof(message), $"Message protocol '{message.Protocol}' not found in negociated protocols '{negociatedProtocols}'.");

        return WriteWireHeader( 1 + (uint)protocolNumber, (uint)message.Message.Length, message.IsControl, header );
    }

    internal static int WriteWireHeader( uint protocolNumber, uint length, bool isControl, Span<byte> header )
    {
        Throw.DebugAssert( header.Length >= MaxWirePrefixLength );
        Throw.DebugAssert( length < int.MaxValue );
        Throw.DebugAssert( protocolNumber >= 0 && protocolNumber <= MessageProtocolMap.MaxCount );
        uint len = (uint)BitOperations.Log2( length ) / 8;
        Throw.DebugAssert( len >= 0 && len <= 3 );
        var b = (len << 6) | protocolNumber;
        if( isControl ) b |= OutgoingMessage.IsControlFlag;
        Throw.DebugAssert( b >= 0 && b <= 255 );
        header[0] = (byte)b;
        if( !BitConverter.IsLittleEndian ) length = BinaryPrimitives.ReverseEndianness( length );
        Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( header ), 1 ), length );
        return (int)len + 2;
    }

    sealed class StaticEmpty : IOutgoingMessage
    {
        readonly int _ackOrEmptyAck;

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

        public void Dispose()
        {
        }

        public void Release()
        {
        }
    }

}
