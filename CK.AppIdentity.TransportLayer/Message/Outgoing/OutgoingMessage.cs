using CK.Core;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer
{
    sealed class OutgoingMessage : IOutgoingMessage
    {
        internal const int MaxPrefixLength = 5;
        internal const int IsControlFlag = 0b00100000;

        readonly OutgoingMessageFactory _messageFactory;
        readonly MutableSequence<byte> _buffer;
        readonly object? _source;
        readonly ReadOnlySequence<byte> _message;
        readonly bool _isControl;
        int _refCount;
        int _protocolNumber;

        internal OutgoingMessage( OutgoingMessageFactory factory, MutableSequence<byte> buffer, object? source, bool isControl )
        {
            Debug.Assert( buffer.Length > 0 && buffer.Length <= int.MaxValue );

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

        public int Length => (int)_buffer.Length;

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
                Debug.Assert( _buffer != null );
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
                Debug.Assert( _buffer != null );
                lock( _buffer )
                {
                    if( _refCount != 0 && --_refCount == 0 )
                    {
                        Debug.Assert( _messageFactory != null );
                        _messageFactory.Release( _buffer );
                    }
                }
            }
        }

        public void Dispose() => Release();

        internal void SetProtocolNumber( int protocolNumber )
        {
            Debug.Assert( protocolNumber >= 0 && protocolNumber <= MessageProtocolMap.MaxCount );
            _protocolNumber = protocolNumber;
        }

        internal int GetProtocolNumber() => _protocolNumber;

        internal int WriteWireHeader( Span<byte> header )
        {
            Debug.Assert( header.Length >= MaxPrefixLength );
            var messageLength = (uint)_buffer.Length;
            uint len = (uint)BitOperations.Log2( (uint)_buffer.Length ) / 8;
            Debug.Assert( len >= 0 && len <= 3 );
            var b = (len << 6) | (uint)_protocolNumber;
            if( _isControl ) b |= IsControlFlag;
            Debug.Assert( b >= 0 && b <= 255 );
            header[0] = (byte)b;
            if( !BitConverter.IsLittleEndian ) messageLength = BinaryPrimitives.ReverseEndianness( messageLength );
            Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( header ), 1 ), messageLength );
            return (int)len + 2;
        }


    }
}
