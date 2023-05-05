using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Message
{
    public static class Extensions
    {
        internal static WirePrefixedTransportMessage AddWirePrefix( this TransportMessageImpl message )
        {
            var memory = MemoryPool<byte>.Shared.Rent( 5 );
            var bufferLength = WritePrefix( message.IsControl, (uint)message.Payload.Length, memory.Memory.Span );
            return new WirePrefixedTransportMessage( message, memory, bufferLength );
        }

        const int _maxPrefixLength = 5;

        static int WritePrefix( bool isControl, uint messageLength, Span<byte> memory )
        {
            Debug.Assert( memory.Length >= _maxPrefixLength );
            Debug.Assert( messageLength >= 0 );

            uint len = (uint)BitOperations.Log2( messageLength ) / 8;

            Debug.Assert( len >= 0 && len <= 3 );

            var b = (len << 6);

            if( isControl ) b |= WirePrefixedTransportMessage.IsControlFlag;

            Debug.Assert( b >= 0 && b <= 255 );

            memory[0] = (byte)b;

            if( !BitConverter.IsLittleEndian ) messageLength = BinaryPrimitives.ReverseEndianness( messageLength );

            Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( memory ), 1 ), messageLength );

            return (int)len + 2;

        }

    }
}
