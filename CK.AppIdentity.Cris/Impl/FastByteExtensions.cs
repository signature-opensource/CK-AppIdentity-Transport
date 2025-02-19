using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using System;

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

    public static void WriteReadLogKey( this ref FastByteWriter w, in ActivityMonitor.LogKey id )
    {
        w.WriteString( id.OriginatorId );
        w.WriteDateTimeStamp( id.CreationDate );
    }

    public static ActivityMonitor.LogKey ReadLogKey( this ref FastByteReader r )
    {
        return new ActivityMonitor.LogKey( r.ReadString(), r.ReadDateTimeStamp() );
    }

    public static void WriteFormattedString( ref FastByteWriter w, FormattedString formattedString )
    {
        w.WriteNullableString( formattedString.Text );
        if( formattedString.Text != null )
        {
            w.WriteSmallUInt32( (uint)formattedString.Placeholders.Count );
            foreach( var (start, length) in formattedString.Placeholders )
            {
                w.WriteSmallUInt32( (uint)start );
                w.WriteSmallUInt32( (uint)length );
            }
            w.WriteString( formattedString.Culture.Name );
        }
    }

    public static FormattedString ReadFormattedString( ref FastByteReader r )
    {
        string? text = r.ReadNullableString();
        if( text == null ) return default;

        uint num = r.ReadSmallUInt32();
        var placeholders = new (int, int)[num];
        for( int i = 0; i < num; i++ )
        {
            ref (int Start, int Length) reference = ref placeholders[i];
            reference.Start = (int)r.ReadSmallUInt32();
            reference.Length = (int)r.ReadSmallUInt32();
        }
        var culture = NormalizedCultureInfo.GetNormalizedCultureInfo( r.ReadString() );
        return FormattedString.CreateFromProperties( text, placeholders, culture );
    }


    public static void WriteCodeString( ref FastByteWriter w, CodeString codeString )
    {
        WriteFormattedString( ref w, codeString.FormattedString );
        w.WriteString( codeString.ResName );
    }

    public static CodeString ReadCodeString( ref FastByteReader r )
    {
        var formatted = ReadFormattedString( ref r );
        return CodeString.CreateFromProperties( formatted, r.ReadString() );
    }

    public static void WriteMCString( ref FastByteWriter w, MCString message )
    {
        w.WriteString( message.Text );
        w.WriteString( message.FormatCulture.Name );
        WriteCodeString( ref w, message.CodeString );
    }

    public static MCString ReadMCString( this ref FastByteReader r )
    {
        var text = r.ReadString();
        var formatCulture = NormalizedCultureInfo.GetNormalizedCultureInfo( r.ReadString() );
        return MCString.CreateFromProperties( text, ReadCodeString( ref r ), formatCulture );
    }

    public static void WriteUserMessage( this ref FastByteWriter w, in UserMessage message )
    {
        var level = (int)message.Level;
        w.WriteSmallInt32( level );
        if( level > 0 )
        {
            w.WriteByte( message.Depth );
            WriteMCString( ref w, message.Message );
        }
    }

    public static UserMessage ReadUserMessage( this ref FastByteReader r )
    {
        var level = r.ReadSmallInt32();
        if( level == 0 ) return default;
        var depth = r.ReadByte();
        return new UserMessage( (UserMessageLevel)level, ReadMCString( ref r ), depth );
    }

    public static void WriteCrisValidationResult( this ref FastByteWriter w, CrisValidationResult result )
    {
        int count = result.Messages.Count;
        w.WriteSmallInt32( count );
        if( count > 0 )
        {
            foreach( var m in result.Messages )
            {
                WriteUserMessage( ref w, m );
            }
        }
        w.WriteBool( result.Success );
        w.WriteNullableString( result.LogKey );
    }

    public static CrisValidationResult ReadCrisValidationResult( this ref FastByteReader r )
    {
        int count = r.ReadSmallInt32();
        UserMessage[] messages;
        if( count > 0 )
        {
            messages = new UserMessage[count];
            for( int i = 0; i < count; i++ )
            {
                messages[i] = ReadUserMessage( ref r );
            }
        }
        else
        {
            messages = Array.Empty<UserMessage>();
        }
        return new CrisValidationResult( messages, r.ReadNullableString() );
    }

}
