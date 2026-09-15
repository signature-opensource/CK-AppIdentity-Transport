using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.Numerics;

namespace CK.AppIdentity.TransportLayer.Tests;


[TestFixture]
public class BufferingTests
{
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
            r.ReadInt32().ShouldBe( DefInt32 );
            r.ReadUInt32().ShouldBe( DefUInt32 );
            r.ReadInt64().ShouldBe( DefInt64 );
            r.ReadUInt64().ShouldBe( DefUInt64 );
            r.ReadInt16().ShouldBe( DefInt16 );
            r.ReadUInt16().ShouldBe( DefUInt16 );
            r.ReadByte().ShouldBe( DefByte );
            r.ReadSByte().ShouldBe( DefSByte );
            r.ReadDateTime().ShouldBe( DefDateTime );
            r.ReadTimeSpan().ShouldBe( DefTimeSpan );

            r.ReadString().ShouldBe( DefString );

            r.ReadDateTimeOffset().ShouldBe( DefDateTimeOffset );
            r.ReadGuid().ShouldBe( DefGuid );
            r.ReadDouble().ShouldBe( DefDouble );
            r.ReadSingle().ShouldBe( DefSingle );
            r.ReadHalf().ShouldBe( DefHalf );
            r.ReadChar().ShouldBe( DefChar );
            r.ReadBool().ShouldBe( DefBoolean );
            r.ReadIndex().ShouldBe( DefIndex );
            r.ReadRange().ShouldBe( DefRange );
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
            r.ReadNullableInt32().ShouldBe( null );
            r.ReadNullableInt32().ShouldBe( Int32.MinValue );
            r.ReadNullableInt32().ShouldBe( Int32.MaxValue );
            r.ReadNullableInt32().ShouldBe( 126 );
        } ).ShouldBe( 1 + 3 * (1 + 4) );
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
            (BitOperations.Log2( 127 ) / 7 + 1).ShouldBe( 1 );
            //// 2 bytes.
            w.WriteSmallUInt64( 128 );
            w.WriteSmallUInt64( 128 * 128 - 1 );
            (BitOperations.Log2( 128 * 128 - 1 ) / 7 + 1).ShouldBe( 2 );
            // 3 bytes.
            w.WriteSmallUInt64( 128 * 128 );
            w.WriteSmallUInt64( 128 * 128 * 128 - 1 );
            (BitOperations.Log2( 128 * 128 * 128 - 1 ) / 7 + 1).ShouldBe( 3 );
            // 4 bytes.
            w.WriteSmallUInt64( 128 * 128 * 128 );
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 - 1 );
            (BitOperations.Log2( 128 * 128 * 128 * 128 - 1 ) / 7 + 1).ShouldBe( 4 );
            // 5 bytes.
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 );
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L - 1 );
            (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L - 1 ) / 7 + 1).ShouldBe( 5 );
            // 6 bytes.
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L );
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 - 1 );
            (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L * 128 - 1 ) / 7 + 1).ShouldBe( 6 );
            // 7 bytes.
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 );
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 - 1 );
            (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L * 128 * 128 - 1 ) / 7 + 1).ShouldBe( 7 );
            // 8 bytes.
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 );
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 - 1 );
            (BitOperations.Log2( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 - 1 ) / 7 + 1).ShouldBe( 8 );
            // 9 bytes.
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 );
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 - 1 );
            (BitOperations.Log2( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 - 1) / 7 + 1).ShouldBe( 9 );
            // 10 bytes.
            w.WriteSmallUInt64( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 );
            w.WriteSmallUInt64( UInt64.MaxValue );
            (BitOperations.Log2( UInt64.MaxValue ) / 7 + 1).ShouldBe( 10 );

            w.Commit();
        }, sequence =>
        {
            var r = new FastByteReader( sequence );
            r.ReadSmallUInt64().ShouldBe( 0 );
            r.ReadSmallUInt64().ShouldBe( 127 );
            r.ReadSmallUInt64().ShouldBe( 128 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L * 128 - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L * 128 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L * 128 * 128 - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L * 128 * 128 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128L * 128 * 128 * 128 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 - 1 );
            r.ReadSmallUInt64().ShouldBe( 128 * 128 * 128 * 128 * 128UL * 128 * 128 * 128 * 128 );
            r.ReadSmallUInt64().ShouldBe( UInt64.MaxValue );
        } ).ShouldBe( 2 * 10*11/2, "n(n+1)/2 is the sum of the first integers up to n ;)." );
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
                r.ReadByte().ShouldBe( (byte)((i << 1) + 1) );
                r.ReadByte().ShouldBe( (byte)((i << 1) + 1) );
            }
        } ).ShouldBe( 2 * 128 );
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
            r.ReadNullableChar().ShouldBe( null );
            r.ReadNullableChar().ShouldBe( Char.MinValue );
            r.ReadNullableChar().ShouldBe( (char)(Char.MinValue + 1) );
            r.ReadNullableChar().ShouldBe( Char.MaxValue );
        } ).ShouldBe( 1 + 1 + 1 + 3, "Nullable char are int length encoded. MaxValue requires 3 bytes." );

        ReadWrite( bytes =>
        {
            var w = new FastByteWriter( bytes );
            w.WriteNullableChar( 'の' ); // 'HIRAGANA LETTER NO' (U+306E - UTF-8: 0xE3 0x81 0xAE)
            w.Commit();
        }, sequence =>
        {
            var r = new FastByteReader( sequence );
            r.ReadNullableChar().ShouldBe( 'の' );
        } ).ShouldBe( 2, "Nullable char are int length encoded, not Utf8 encoding." );

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
            r.ReadNullableChar().ShouldBeNull();
            for( int i = 0x00; i < Char.MaxValue - 1; ++i )
            {
                //char c = Convert.ToChar( i );
                //if( char.IsSurrogate( c ) ) continue;
                r.ReadNullableChar().ShouldBe( (char)i );
            }
        } );
    }

    [Test]
    public void nullable_double()
    {
        var nan1 = BitConverter.Int64BitsToDouble( -1 );
        var nan2 = BitConverter.Int64BitsToDouble( long.MaxValue );
        double.IsNaN( nan1 ).ShouldBeTrue();
        double.IsNaN( nan2 ).ShouldBeTrue();
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
            r.ReadNullableDouble().ShouldBe( nan2 );
            r.ReadNullableDouble().ShouldBe( nan1 );
            r.ReadNullableDouble().ShouldBe( null );
            r.ReadNullableDouble().ShouldBe( Math.PI );
        } )
        .ShouldBe( 1 + 3 * (1 + 8) );
    }

    [Test]
    public void nullable_float()
    {
        var nan1 = BitConverter.Int32BitsToSingle( -1 );
        var nan2 = BitConverter.Int32BitsToSingle( int.MaxValue );
        float.IsNaN( nan1 ).ShouldBeTrue();
        float.IsNaN( nan2 ).ShouldBeTrue();
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
            r.ReadNullableSingle().ShouldBe( nan2 );
            r.ReadNullableSingle().ShouldBe( nan1 );
            r.ReadNullableSingle().ShouldBe( null );
            r.ReadNullableSingle().ShouldBe( (float)Math.PI );
        } )
        .ShouldBe( 1 + 3 * (1 + 4) );
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
            r.ReadString().ShouldBe( "" );
        } ).ShouldBe( 1, "An empty string is only one byte." );


        ReadWrite( bytes =>
        {
            var random = new Random( minimumBufferSize );
            var w = new FastByteWriter( bytes );
            string s = "";
            for( int i = 1; i < 75000; i += random.Next( 10 ) )
            {
                s += 'a';
                w.WriteString( s );
            }
            w.Commit();
        }, sequence =>
        {
            var random = new Random( minimumBufferSize );
            var r = new FastByteReader( sequence );
            string s = "";
            for( int i = 1; i < 75000; i += random.Next( 10 ) )
            {
                s += 'a';
                r.ReadString().ShouldBe( s, $"Round n°{i}." );
            }
        }, minimumBufferSize: minimumBufferSize );
    }

    static int ReadWrite( Action<MutableSequence<byte>> writer, Action<ReadOnlySequence<byte>>? reader = null, int minimumBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
    {
        using( var mem = new MutableSequence<byte>() {  MinimumBufferSize = minimumBufferSize } )
        {
            writer( mem );
            reader?.Invoke( mem.GetReadOnlySequence() );
            return (int)mem.Length;
        }
    }
}
