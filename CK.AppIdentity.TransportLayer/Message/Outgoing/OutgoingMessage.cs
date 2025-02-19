using CK.Core;
using System.Buffers;

namespace CK.AppIdentity.TransportLayer;

sealed class OutgoingMessage : IOutgoingMessage
{
    internal const int IsControlFlag = 0b00100000;

    readonly OutgoingMessageFactory _messageFactory;
    readonly MutableSequence<byte> _buffer;
    readonly object? _source;
    readonly ReadOnlySequence<byte> _message;
    readonly bool _isControl;
    int _refCount;

    internal OutgoingMessage( OutgoingMessageFactory factory, MutableSequence<byte> buffer, object? source, bool isControl )
    {
        Throw.DebugAssert( buffer.Length > 0 && buffer.Length <= int.MaxValue );

        _messageFactory = factory;
        _buffer = buffer;
        _message = buffer.GetReadOnlySequence();
        _source = source;
        _isControl = isControl;
        _refCount = 1;
    }

    public MessageProtocol Protocol => _messageFactory.Protocol;

    public object? Source => _source;

    public bool IsValid => _refCount != 0;

    public bool IsControl => _isControl;
    
    public bool IsData => !_isControl;

    public ReadOnlySequence<byte> Message
    {
        get
        {
            Throw.CheckState( IsValid );
            return _message;
        }
    }

    public void AddRef()
    {
        if( _refCount != 0 )
        {
            Throw.DebugAssert( _buffer != null );
            lock( _buffer )
            {
                if( _refCount != 0 )
                {
                    ++_refCount;
                }
            }
        }
    }

    public void Release()
    {
        if( _refCount != 0 )
        {
            Throw.DebugAssert( _buffer != null );
            lock( _buffer )
            {
                if( _refCount != 0 && --_refCount == 0 )
                {
                    Throw.DebugAssert( _messageFactory != null );
                    _messageFactory.Release( _buffer );
                }
            }
        }
    }

    public void Dispose() => Release();
}
