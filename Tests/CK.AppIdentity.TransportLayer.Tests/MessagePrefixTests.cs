using CK.Core;
using FluentAssertions;
using NUnit.Framework;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer.Tests
{
    [TestFixture]
    public class MessagePrefixTests
    {
        [Test]
        public void NOT_USED_Max_PrefixLength_is_between_1_and_5_bytes()
        {
            using var m = new MemoryStream();
            var w = new BinaryWriter( m );

            w.Write7BitEncodedInt64( 127 );
            m.Position.Should().Be( 1 );

            m.Position = 0;
            w.Write7BitEncodedInt64( int.MaxValue );
            m.Position.Should().Be( 5 );
        }

        [Test]
        public void NOT_USED_Write_and_Read_with_loop_prefix_length()
        {
            const int _maxPrefixLength = 5;

            WriteAndRead( 0 ).Should().Be( 1 );
            WriteAndRead( 1 ).Should().Be( 1 );
            WriteAndRead( 2 ).Should().Be( 1 );

            WriteAndRead( 128 - 1 ).Should().Be( 1 );
            WriteAndRead( 128 ).Should().Be( 2 );

            WriteAndRead( 128 * 128 - 1 ).Should().Be( 2 );
            WriteAndRead( 128 * 128 ).Should().Be( 3 );

            WriteAndRead( 128 * 128 * 128 - 1 ).Should().Be( 3 );
            WriteAndRead( 128 * 128 * 128 ).Should().Be( 4 );

            WriteAndRead( 128 * 128 * 128 * 128 - 1 ).Should().Be( 4 );
            WriteAndRead( 128 * 128 * 128 * 128 ).Should().Be( 5 );

            WriteAndRead( int.MaxValue - 1 ).Should().Be( 5 );
            WriteAndRead( int.MaxValue ).Should().Be( 5 );

            static int WriteAndRead( int len )
            {
                Span<byte> memory = stackalloc byte[5];
                int prefixLen = WriteLength( (uint)len, memory );
                prefixLen.Should().BeLessThanOrEqualTo( 5 );
                int readLen = ReadLength( memory, out int readPrefixLen );
                readPrefixLen.Should().Be( prefixLen );
                readLen.Should().Be( len );
                return prefixLen;
            }

            static int WriteLength( uint value, Span<byte> memory )
            {
                int i = 0;
                while( value > 0x7Fu )
                {
                    memory[i++] = (byte)(value | ~0x7Fu);
                    value >>= 7;
                }
                memory[i++] = (byte)value;
                return i;
            }
            static int ReadLength( Span<byte> header, out int prefixLength )
            {
                int pLen;
                uint result = 0;
                uint b;
                int bitShift = 0;
                for( pLen = 0; pLen < _maxPrefixLength; )
                {
                    b = header[pLen++];
                    result |= (b & 0x7F) << bitShift;
                    if( b <= 0x7F )
                    {
                        prefixLength = pLen;
                        return (int)result;
                    }
                    bitShift += 7;
                }
                prefixLength = pLen;
                b = header[_maxPrefixLength];
                // The last one cannot be a continuation.
                if( b > 0x7Fu ) return 0;
                return (int)(result | (b << bitShift));
            }
        }

        [Test]
        public void NOT_USED_Write_and_Read_optimized_prefix_length_with_optional_4_bits_highState()
        {
            WriteAndRead( 0, 0 ).Should().Be( 1 );
            WriteAndRead( 1, 0 ).Should().Be( 1 );
            WriteAndRead( 2, 0 ).Should().Be( 1 );

            WriteAndRead( 128 - 1, 0 ).Should().Be( 1 );
            WriteAndRead( 128, 0 ).Should().Be( 2 );

            WriteAndRead( 128 * 128 - 1, 0 ).Should().Be( 2 );
            WriteAndRead( 128 * 128, 0 ).Should().Be( 3 );

            WriteAndRead( 128 * 128 * 128 - 1, 0 ).Should().Be( 3 );
            WriteAndRead( 128 * 128 * 128, 0 ).Should().Be( 4 );

            WriteAndRead( 128 * 128 * 128 * 128 - 1, 0 ).Should().Be( 4 );
            WriteAndRead( 128 * 128 * 128 * 128, 0 ).Should().Be( 5 );

            WriteAndRead( int.MaxValue - 1, 0 ).Should().Be( 5 );
            WriteAndRead( int.MaxValue, 0 ).Should().Be( 5 );

            // When highState is non 0, we always need 5 bytes for the prefix.
            // Maximal highState is 15: 4 bits are available for flags with the 5 bytes prefix.
            WriteAndRead( 1, 1 ).Should().Be( 5 );
            WriteAndRead( 3712, 2 ).Should().Be( 5 );
            WriteAndRead( 46157676, 3 ).Should().Be( 5 );
            WriteAndRead( 8, 4 ).Should().Be( 5 );
            WriteAndRead( int.MaxValue, 5 ).Should().Be( 5 );
            WriteAndRead( int.MaxValue, 8 ).Should().Be( 5 );
            WriteAndRead( int.MaxValue, 15 ).Should().Be( 5 );
            FluentActions.Invoking( () => WriteAndRead( int.MaxValue, 16 ) ).Should().Throw<ArgumentException>( "It ends here." );

            static int WriteAndRead( int value, byte highState )
            {
                Span<byte> memory = stackalloc byte[5];
                int prefixLen = WriteLength( value, memory, highState );
                Throw.CheckArgument( prefixLen <= 5 );
                int readLen = ReadLength( memory, out int readPrefixLen, out byte readHighState );
                readPrefixLen.Should().Be( prefixLen );
                readHighState.Should().Be( highState );
                readLen.Should().Be( value );
                return prefixLen;
            }

            static int WriteLength( int value, Span<byte> memory, byte highState )
            {
                ulong uValue = (ulong)(uint)value | ((ulong)highState << 31);
                var neededBytes = (int)((uint)BitOperations.Log2( uValue ) / 7);
                ulong lower = ((uValue << 1) + 1) << neededBytes;
                if( !BitConverter.IsLittleEndian ) lower = BinaryPrimitives.ReverseEndianness( lower );
                Unsafe.WriteUnaligned( ref MemoryMarshal.GetReference( memory ), lower );
                return neededBytes + 1;
            }

            static int ReadLength( Span<byte> header, out int prefixLength, out byte highState )
            {
                ref byte readHead = ref MemoryMarshal.GetReference( header );
                ulong result = Unsafe.ReadUnaligned<ulong>( ref readHead );
                var bytesNeeded = BitOperations.TrailingZeroCount( (uint)result ) + 1;
                prefixLength = bytesNeeded;
                if( bytesNeeded > 5 )
                {
                    highState = 0;
                    return 0;
                }
                result &= (1UL << (bytesNeeded * 8)) - 1;
                result >>= bytesNeeded;
                highState = (byte)(result >> 31);
                return (int)(result & int.MaxValue);
            }

        }
    }
}
