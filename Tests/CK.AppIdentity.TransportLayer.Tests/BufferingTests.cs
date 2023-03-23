using CK.Core;
using FluentAssertions;
using NUnit.Framework;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer.Tests
{
    [TestFixture]
    public class BufferingTests
    {
        [Test]
        public void Max_PrefixLength_is_between_1_and_5_bytes()
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
        public void Write_and_Read_with_loop_prefix_length()
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
        public void Write_and_Read_optimized_prefix_length_with_optional_4_bits_highState()
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

            // When highState is non 0, we aways need 5 bytes for the prefix.
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

        public static readonly string DefString = "MultiPropertyType";
        public static readonly Guid DefGuid = new Guid( "4F5E996D-51E9-4B04-B572-5126B14A5ECA" );
        public static readonly int DefInt32 = -42;
        public static readonly uint DefUInt32 = 42;
        public static readonly long DefInt64 = -42 << 48;
        public static readonly ulong DefUInt64 = 42 << 48;
        public static readonly short DefInt16 = -3712;
        public static readonly ushort DefUInt16 = 3712;
        public static readonly byte DefByte = 255;
        public static readonly sbyte DefSByte = -128;
        public static readonly DateTime DefDateTime = new DateTime( 2018, 9, 5, 16, 6, 47, DateTimeKind.Local );
        public static readonly TimeSpan DefTimeSpan = new TimeSpan( 3, 2, 1, 59, 995 );
        public static readonly DateTimeOffset DefDateTimeOffset = new DateTimeOffset( DefDateTime, TimeZoneInfo.Local.GetUtcOffset( DefDateTime ) );
        public static readonly double DefDouble = 35.9783e-78;
        public static readonly float DefSingle = (float)0.38974e-4;
        public static readonly Half DefHalf = (Half)0.77623e-5;
        public static readonly char DefChar = 'c';
        public static readonly bool DefBoolean = true;
        public static readonly Index DefIndex = new Index( 3712, true );
        public static readonly Range DefRange = 5..^7;

        [Test]
        public void basic_types_writing_and_reading()
        {
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteInt32( DefInt32 );
                w.WriteUInt32( DefUInt32 );
                w.WriteInt64( DefInt64 );
                w.WriteUInt64( DefUInt64 );
                w.WriteInt16( DefInt16 );
                w.WriteUInt16( DefUInt16 );
                w.WriteByte( DefByte );
                w.WriteSByte( DefSByte );
                w.WriteDateTime( DefDateTime );
                w.WriteTimeSpan( DefTimeSpan );

                w.WriteString( DefString );

                w.WriteDateTimeOffset( DefDateTimeOffset );
                w.WriteGuid( DefGuid );
                w.WriteDouble( DefDouble );
                w.WriteSingle( DefSingle );
                w.WriteHalf( DefHalf );
                w.WriteChar( DefChar );
                w.WriteBool( DefBoolean );
                w.WriteIndex( DefIndex );
                w.WriteRange( DefRange );

                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadInt32().Should().Be( DefInt32 );
                r.ReadUInt32().Should().Be( DefUInt32 );
                r.ReadInt64().Should().Be( DefInt64 );
                r.ReadUInt64().Should().Be( DefUInt64 );
                r.ReadInt16().Should().Be( DefInt16 );
                r.ReadUInt16().Should().Be( DefUInt16 );
                r.ReadByte().Should().Be( DefByte );
                r.ReadSByte().Should().Be( DefSByte );
                r.ReadDateTime().Should().Be( DefDateTime );
                r.ReadTimeSpan().Should().Be( DefTimeSpan );

                r.ReadString().Should().Be( DefString );

                r.ReadDateTimeOffset().Should().Be( DefDateTimeOffset );
                r.ReadGuid().Should().Be( DefGuid );
                r.ReadDouble().Should().Be( DefDouble );
                r.ReadSingle().Should().Be( DefSingle );
                r.ReadHalf().Should().Be( DefHalf );
                r.ReadChar().Should().Be( DefChar );
                r.ReadBool().Should().Be( DefBoolean );
                r.ReadIndex().Should().Be( DefIndex );
                r.ReadRange().Should().Be( DefRange );
            } );
        }

        [Test]
        public void nullable_types_size_check_Int32()
        {
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteNullableInt32( null );
                w.WriteNullableInt32( Int32.MinValue );
                w.WriteNullableInt32( Int32.MaxValue );
                w.WriteNullableInt32( 126 );
                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadNullableInt32().Should().Be( null );
                r.ReadNullableInt32().Should().Be( Int32.MinValue );
                r.ReadNullableInt32().Should().Be( Int32.MaxValue );
                r.ReadNullableInt32().Should().Be( 126 );
            } ).Should()
            .Be( 1 + 3 * (1 + 4) );
        }

        [Test]
        public void small_UInt64_take_between_1_and_10_bytes()
        {
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                //// 1 byte
                w.WriteSmallUInt64( 0 );
                w.WriteSmallUInt64( 127 );
                (BitOperations.Log2( 127 ) / 7 + 1).Should().Be( 1 );
                //// 2 bytes.
                w.WriteSmallUInt64( 128 );
                w.WriteSmallUInt64( 128 * 128 - 1 );
                (BitOperations.Log2( 128 * 128 - 1 ) / 7 + 1).Should().Be( 2 );
                // 3 bytes.
                w.WriteSmallUInt64( 128 * 128 );
                w.WriteSmallUInt64( 128 * 128 * 128 - 1 );
                (BitOperations.Log2( 128 * 128 * 128 - 1 ) / 7 + 1).Should().Be( 3 );
                // 4 bytes.
                w.WriteSmallUInt64( 128 * 128 * 128 );
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 - 1 );
                (BitOperations.Log2( 128 * 128 * 128 * 128 - 1 ) / 7 + 1).Should().Be( 4 );
                // 5 bytes.
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 );
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L - 1 );
                (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L - 1 ) / 7 + 1).Should().Be( 5 );
                // 6 bytes.
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L );
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 - 1 );
                (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L * 128 - 1 ) / 7 + 1).Should().Be( 6 );
                // 7 bytes.
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 );
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 - 1 );
                (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L * 128 * 128 - 1 ) / 7 + 1).Should().Be( 7 );
                // 8 bytes.
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 );
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 - 1 );
                (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 - 1 ) / 7 + 1).Should().Be( 8 );
                // 9 bytes.
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 );
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 - 1 );
                (BitOperations.Log2( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 - 1) / 7 + 1).Should().Be( 9 );
                // 10 bytes.
                w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 );
                w.WriteSmallUInt64( UInt64.MaxValue );
                (BitOperations.Log2( UInt64.MaxValue ) / 7 + 1).Should().Be( 10 );

                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadSmallUInt64().Should().Be( 0 );
                r.ReadSmallUInt64().Should().Be( 127 );
                r.ReadSmallUInt64().Should().Be( 128 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L * 128 - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L * 128 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L * 128 * 128 - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L * 128 * 128 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 - 1 );
                r.ReadSmallUInt64().Should().Be( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 );
                r.ReadSmallUInt64().Should().Be( UInt64.MaxValue );
            } ).Should()
            .Be( 2 * 10*11/2, "n(n+1)/2 is the sum of the first integers up to n ;)." );
        }

        [Test]
        public void small_UNSIGNED_integer_byte_values()
        {
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                for( uint i = 0; i < 128; ++i )
                {
                    w.WriteSmallUInt32( i );
                    w.WriteSmallUInt64( i );
                }

                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                for( uint i = 0; i < 128; ++i )
                {
                    r.ReadByte().Should().Be( (byte)((i << 1) + 1) );
                    r.ReadByte().Should().Be( (byte)((i << 1) + 1) );
                }
            } ).Should()
            .Be( 2 * 128 );
        }

        [Test]
        public void nullable_types_size_check_Char()
        {
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteNullableChar( null );
                w.WriteNullableChar( Char.MinValue );
                w.WriteNullableChar( (char)(Char.MinValue + 1) );
                w.WriteNullableChar( Char.MaxValue );
                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadNullableChar().Should().Be( null );
                r.ReadNullableChar().Should().Be( Char.MinValue );
                r.ReadNullableChar().Should().Be( (char)(Char.MinValue + 1) );
                r.ReadNullableChar().Should().Be( Char.MaxValue );
            } ).Should()
                .Be( 1 + 1 + 1 + 3, "Nullable char are int length encoded. MaxValue requires 3 bytes." );

            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteNullableChar( 'の' ); // 'HIRAGANA LETTER NO' (U+306E - UTF-8: 0xE3 0x81 0xAE)
                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadNullableChar().Should().Be( 'の' );
            } ).Should()
                .Be( 2, "Nullable char are int length encoded, not Utf8 encoding." );

            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteNullableChar( null );
                // We write Char.MaxValue values (zero based).
                for( int i = 0x00; i < Char.MaxValue - 1; ++i )
                {
                    //char c = Convert.ToChar( i );
                    //if( char.IsSurrogate( c ) ) continue;
                    w.WriteNullableChar( (char)i );
                }
                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadNullableChar().Should().BeNull();
                for( int i = 0x00; i < Char.MaxValue - 1; ++i )
                {
                    //char c = Convert.ToChar( i );
                    //if( char.IsSurrogate( c ) ) continue;
                    r.ReadNullableChar().Should().Be( (char)i );
                }
            } );
        }

        [Test]
        public void nullable_double()
        {
            var nan1 = BitConverter.Int64BitsToDouble( -1 );
            var nan2 = BitConverter.Int64BitsToDouble( long.MaxValue );
            double.IsNaN( nan1 ).Should().BeTrue();
            double.IsNaN( nan2 ).Should().BeTrue();
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteNullableDouble( nan2 );
                w.WriteNullableDouble( nan1 );
                w.WriteNullableDouble( null );
                w.WriteNullableDouble( Math.PI );
                w.Commit();
            },
            sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadNullableDouble().Should().Be( nan2 );
                r.ReadNullableDouble().Should().Be( nan1 );
                r.ReadNullableDouble().Should().Be( null );
                r.ReadNullableDouble().Should().Be( Math.PI );
            } )
            .Should().Be( 1 + 3 * (1 + 8) );
        }

        [Test]
        public void nullable_float()
        {
            var nan1 = BitConverter.Int32BitsToSingle( -1 );
            var nan2 = BitConverter.Int32BitsToSingle( int.MaxValue );
            float.IsNaN( nan1 ).Should().BeTrue();
            float.IsNaN( nan2 ).Should().BeTrue();
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteNullableSingle( nan2 );
                w.WriteNullableSingle( nan1 );
                w.WriteNullableSingle( null );
                w.WriteNullableSingle( (float)Math.PI );
                w.Commit();
            },
            sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadNullableSingle().Should().Be( nan2 );
                r.ReadNullableSingle().Should().Be( nan1 );
                r.ReadNullableSingle().Should().Be( null );
                r.ReadNullableSingle().Should().Be( (float)Math.PI );
            } )
            .Should().Be( 1 + 3 * (1 + 4) );
        }

        [TestCase( 16 )]
        [TestCase( 17 )]
        [TestCase( 18 )]
        [TestCase( 512 )]
        [TestCase( 4096 )]
        public void string_read_write( int minimumBufferSize )
        {
            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                w.WriteString( "" );
                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                r.ReadString().Should().Be( "" );
            } ).Should()
                .Be( 1, "An empty string is only one byte." );

            ReadWrite( bytes =>
            {
                var w = new FastByteWriter( bytes );
                string s = "";
                for( int i = 1; i < 75000; ++i )
                {
                    s += 'a';
                    w.WriteString( s );
                }
                w.Commit();
            }, sequence =>
            {
                var r = new FastByteReader( sequence );
                string s = "";
                for( int i = 1; i < 75000; ++i )
                {
                    s += 'a';
                    r.ReadString().Should().Be( s, $"Round n°{i}." );
                }
            }, minimumBufferSize: minimumBufferSize );
        }

        static int ReadWrite( Action<IBufferWriter<byte>> writer, Action<ReadOnlySequence<byte>>? reader = null, int minimumBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            using( var mem = new MutableSequence<byte>() {  MinimumBufferSize = minimumBufferSize } )
            {
                writer( mem );
                reader?.Invoke( mem.GetReadOnlySequence() );
                return (int)mem.Length;
            }
        }
    }
}
