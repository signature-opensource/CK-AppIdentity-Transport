using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    public ref partial struct FastByteWriter
    {
        public void WriteNullableBool( bool? b ) => WriteByte( b switch { true => 1, false => 2, null => 3 } );

        public void WriteNullableInt32( int? value )
        {
            if( value.HasValue )
            {
                WriteByte( 1 );
                WriteInt32( value.Value );
            }
            else WriteByte( 0 );
        }

        public void WriteNullableSingle( float? value )
        {
            if( value.HasValue )
            {
                WriteByte( 1 );
                WriteSingle( value.Value );
            }
            else WriteByte( 0 );
        }

        public void WriteNullableDouble( double? value )
        {
            if( value.HasValue )
            {
                WriteByte( 1 );
                WriteDouble( value.Value );
            }
            else WriteByte( 0 );
        }

        public void WriteNullableChar( char? value )
        {
            if( value.HasValue )
            {
                WriteSmallUInt32( ((uint)value.Value) + 1 );
            }
            else
            {
                // 0 encoded length is 1.
                WriteByte( 1 );
            }
        }

    }

}

