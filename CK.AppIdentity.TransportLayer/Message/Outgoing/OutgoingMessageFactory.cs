using CK.Core;
using System;
using System.Buffers;
using System.Threading;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Factory for <see cref="OutgoingMessageBuilder"/>.
/// There is only 2 ways to create an outgoing transport message:
/// <list type="number">
/// <item><see cref="CreateBuilder(int)"/> (and then <see cref="OutgoingMessageBuilder.CreateMessage"/>) for regular messages (that must be disposed).</item>
/// <item><see cref="CreateStatic(Action{MutableSequence{byte}}, bool, int)"/> for messages that can be kept without the need to be disposed.</item>
/// </list>
/// <para>
/// This class is thread safe.
/// </para>
/// </summary>
public sealed class OutgoingMessageFactory : IDisposable
{
    readonly MessageProtocol _protocol;
    MutableSequence<byte>? _cachedOneBuffer;

    /// <summary>
    /// Initializes a new message factory for a protocol and its protocol number.
    /// </summary>
    /// <param name="protocol">The protocol. Must not be the "0 Protocol".</param>
    public OutgoingMessageFactory( MessageProtocol protocol )
    {
        Throw.CheckArgument( protocol != null && protocol != MessageProtocol.ZeroProtocol );
        _protocol = protocol;
    }

    /// <summary>
    /// Gets the protocol that this factory uses.
    /// </summary>
    public MessageProtocol Protocol => _protocol;

    /// <summary>
    /// The single length gate for every outgoing message of this protocol.
    /// <para>
    /// The cap is the same number the receiver applies (<see cref="MessageProtocol.MaxIncomingMessageLength"/>).
    /// A frame above it is one a conforming peer MUST refuse, and refusing it kills the transport,
    /// because by then the message has been consumed off the wire and cannot be skipped. Failing here
    /// turns a dropped link into a local exception at the call site that built the oversized message,
    /// which is where the mistake actually is.
    /// </para>
    /// <para>
    /// <see cref="MessageProtocol.MaxIncomingMessageLength"/> is an <see cref="int"/>, so this also
    /// subsumes the "larger than int.MaxValue" check.
    /// </para>
    /// </summary>
    /// <param name="length">The buffered length.</param>
    internal void CheckMessageLength( long length )
    {
        if( length == 0 )
        {
            Throw.InvalidOperationException( "No data has been written to the outgoing message." );
        }
        if( length > _protocol.MaxIncomingMessageLength )
        {
            Throw.InvalidOperationException( $"Buffered {length} bytes exceeds the {_protocol.MaxIncomingMessageLength} bytes maximum message length of protocol '{_protocol.FullName}'." );
        }
    }

    /// <summary>
    /// Creates a new <see cref="OutgoingMessageBuilder"/>.
    /// Either <see cref="OutgoingMessageBuilder.Dispose"/> or <see cref="OutgoingMessageBuilder.CreateMessage"/> must be called on the builder.
    /// </summary>
    /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
    /// <returns>A message builder.</returns>
    public OutgoingMessageBuilder CreateBuilder( int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
    {
        var buffer = GetBuffer();
        buffer.MinimumBufferSize = minSequenceBufferSize;
        return new OutgoingMessageBuilder( this, buffer );
    }

    /// <summary>
    /// Creates a message that must be <see cref="IRefCounted.Release"/> once done with it.
    /// </summary>
    /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
    /// <param name="isControl">True to set the <see cref="IOutgoingMessage.IsControl"/> bit.</param>
    /// <param name="source">Optional source of the message.</param>
    /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
    /// <returns>An immutable message.</returns>
    public IOutgoingMessage Create( Action<MutableSequence<byte>> writer,
                                    bool isControl = false,
                                    object? source = null,
                                    int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
    {
        var buffer = GetBuffer();
        buffer.MinimumBufferSize = minSequenceBufferSize;
        try
        {
            writer( buffer );
            CheckMessageLength( buffer.Length );
            return new OutgoingMessage( this, buffer, source, isControl );
        }
        catch
        {
            Release( buffer );
            throw;
        }
    }

    /// <summary>
    /// Creates a static snapshot <see cref="IOutgoingMessage"/>, its content is a single independent segment (not pooled).
    /// Disposing/releasing a static message does nothing.
    /// </summary>
    /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
    /// <param name="isControl">True to set the <see cref="IOutgoingMessage.IsControl"/> bit.</param>
    /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
    /// <returns>A static outgoing message.</returns>
    public IOutgoingMessage CreateStatic( Action<MutableSequence<byte>> writer,
                                          bool isControl = false,
                                          int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
    {
        var buffer = GetBuffer();
        buffer.MinimumBufferSize = minSequenceBufferSize;
        try
        {
            writer( buffer );
            CheckMessageLength( buffer.Length );
            return new StaticMessage( _protocol, isControl, buffer.GetReadOnlySequence().ToArray() );
        }
        finally
        {
            Release( buffer );
        }
    }

    sealed class StaticMessage : IOutgoingMessage
    {
        public StaticMessage( MessageProtocol protocol, bool isControl, byte[] content )
        {
            Protocol = protocol;
            IsControl = isControl;
            Message = new ReadOnlySequence<byte>( content );
        }

        public MessageProtocol Protocol { get; }

        public object? Source => null;

        public bool IsValid => true;

        public bool IsControl { get; }

        public bool IsData => !IsControl;

        public ReadOnlySequence<byte> Message { get; }

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

    internal MutableSequence<byte> GetBuffer()
    {
        return Interlocked.Exchange( ref _cachedOneBuffer, null ) ?? new MutableSequence<byte>();
    }

    internal void Release( MutableSequence<byte> buffer )
    {
        buffer.Clear();
        Interlocked.CompareExchange( ref _cachedOneBuffer, buffer, null );
    }

    /// <summary>
    /// Disposes any internal resource.
    /// </summary>
    public void Dispose()
    {
        Interlocked.Exchange( ref _cachedOneBuffer, null )?.Dispose();
    }

}
