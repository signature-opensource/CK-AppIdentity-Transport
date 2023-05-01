using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    static class FastByteExtensions
    {
        public static void WriteDateTimeStamp( this ref FastByteWriter w, DateTimeStamp timeStamp )
        {
            w.WriteDateTime( timeStamp.TimeUtc );
            w.WriteByte( timeStamp.Uniquifier );
        }

        public static DateTimeStamp ReadDateTimeStamp( this ref FastByteReader r )
        {
            return new DateTimeStamp( r.ReadDateTime(), r.ReadByte() );
        }

        public static void WriteReadLogKey( this ref FastByteWriter w, in ActivityMonitor.LogKey id )
        {
            w.WriteString( id.OriginatorId );
            w.WriteDateTimeStamp( id.CreationDate );
        }

        public static ActivityMonitor.LogKey ReadLogKey( this ref FastByteReader r )
        {
            return new ActivityMonitor.LogKey( r.ReadString(), r.ReadDateTimeStamp() );
        }

        public static void WriteReadCrisValidationResult( this ref FastByteWriter w, CrisValidationResult result )
        {
            int count = result.AllEntries.Count;
            w.WriteSmallInt32( count );
            if( count > 0 )
            {
                foreach( var e in result.AllEntries )
                {
                    w.WriteString( e.Text );
                    w.WriteBool( e.IsError );
                }
            }
        }

        public static CrisValidationResult ReadCrisValidationResult( this ref FastByteReader r )
        {
            int count = r.ReadSmallInt32();
            if( count == 0 ) return CrisValidationResult.SuccessResult;
            var entries = new CrisValidationResult.Entry[count];
            for(int i = 0; i < count;i++)
            {
                entries[i] = new CrisValidationResult.Entry( r.ReadString(), r.ReadBool() );
            }
            return new CrisValidationResult( entries );
        }

    }
}
