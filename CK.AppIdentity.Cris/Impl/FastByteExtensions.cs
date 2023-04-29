using CK.AppIdentity.TransportLayer;
using CK.Core;
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

        public static void WriteRequestIdentifier( this ref FastByteWriter w, in RequestIdentifier id )
        {
            w.WriteString( id.OriginatorId );
            w.WriteDateTimeStamp( id.TimeStamp );
        }

        public static RequestIdentifier ReadRequestIdentifier( this ref FastByteReader r )
        {
            return new RequestIdentifier( r.ReadString(), r.ReadDateTimeStamp() );
        }

    }
}
