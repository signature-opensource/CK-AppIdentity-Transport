using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.Cris;

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

    public static void WriteLogKey( this ref FastByteWriter w, in ActivityMonitor.LogKey id )
    {
        w.WriteString( id.OriginatorId );
        w.WriteDateTimeStamp( id.CreationDate );
    }

    public static ActivityMonitor.LogKey ReadLogKey( this ref FastByteReader r )
    {
        return new ActivityMonitor.LogKey( r.ReadString(), r.ReadDateTimeStamp() );
    }
}
