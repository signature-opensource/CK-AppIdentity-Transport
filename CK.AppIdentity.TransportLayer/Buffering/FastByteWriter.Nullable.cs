using CK.Core;
using System;

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

        public void WriteNullableDateTime( DateTime? value )
        {
            if( value.HasValue )
            {
                WriteByte( 1 );
                WriteDateTime( value.Value );
            }
            else WriteByte( 0 );
        }

        public void WriteNullableTimeSpan( TimeSpan? value )
        {
            if( value.HasValue )
            {
                WriteByte( 1 );
                WriteTimeSpan( value.Value );
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

        // TODO: use length == 0 for null and len + 1 non null strings.
        public void WriteNullableString( string? value )
        {
            if( value == null )
            {
                WriteByte( 0 );
            }
            else
            {
                WriteByte( 1 );
                WriteString( value );
            }
        }
    }

}

