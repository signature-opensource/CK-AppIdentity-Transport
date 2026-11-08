using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace CK.AppIdentity.Cris;

/// <summary>
/// The binary form of a <see cref="PartyDescription"/>, announced by a party to its remotes with its accepted commands
/// (see <see cref="CrisChannelFeature"/>).
/// <para>
/// The description and each client application are length-prefixed blocks (<see cref="FastByteWriter.BeginBlock"/>):
/// a reader reads the fields it knows and skips the ones a newer writer adds at the end of a block, and a newer reader
/// of an older block finds the block's end where its newer fields would be.
/// </para>
/// <code>
/// [description]                       a block
///     hasPublicUrl, the public URL
///     count, then [client] per client application: its name, its request path
///     count, the roles
/// </code>
/// </summary>
public static class PartyDescriptionCodec
{
    /// <summary>
    /// Writes a description.
    /// </summary>
    /// <param name="w">The writer.</param>
    /// <param name="description">The description to write.</param>
    public static void Write( ref FastByteWriter w, PartyDescription description )
    {
        Throw.CheckNotNullArgument( description );
        var d = w.BeginBlock();
        w.WriteBool( description.PublicUrl != null );
        if( description.PublicUrl != null ) w.WriteString( description.PublicUrl.ToString() );
        w.WriteInt32( description.ClientApplications.Length );
        foreach( var a in description.ClientApplications )
        {
            var c = w.BeginBlock();
            w.WriteString( a.Name );
            w.WriteString( a.RequestPath );
            w.EndBlock( c );
        }
        w.WriteInt32( description.Roles.Length );
        foreach( var role in description.Roles ) w.WriteString( role );
        w.EndBlock( d );
    }

    /// <summary>
    /// Reads a description written by <see cref="Write(ref FastByteWriter, PartyDescription)"/>. The reader is always
    /// moved after the description's block, even when the description is invalid.
    /// </summary>
    /// <param name="r">The reader.</param>
    /// <param name="error">The reason why the description is invalid.</param>
    /// <returns>The description, or null when it is invalid (see <paramref name="error"/>).</returns>
    public static PartyDescription? Read( ref FastByteReader r, out string? error )
    {
        var d = r.ReadBlock();
        error = null;
        Uri? url = null;
        if( d.ReadBool() ) PartyDescription.TryParsePublicUrl( d.ReadString(), out url, out error );
        int appCount = d.ReadInt32();
        Throw.CheckData( "Invalid client application count.", appCount >= 0 );
        var apps = ImmutableArray.CreateBuilder<ClientApplicationDescription>();
        for( int i = 0; i < appCount; ++i )
        {
            var c = d.ReadBlock();
            var name = c.ReadString();
            var path = c.ReadString();
            if( name.Length == 0 || !path.StartsWith( '/' ) ) error ??= $"Invalid client application '{name}' ('{path}').";
            else apps.Add( new ClientApplicationDescription( name, path ) );
        }
        int roleCount = d.ReadInt32();
        Throw.CheckData( "Invalid role count.", roleCount >= 0 );
        var roles = new List<string>();
        for( int i = 0; i < roleCount; ++i )
        {
            var role = d.ReadString();
            if( string.IsNullOrWhiteSpace( role ) ) error ??= "Invalid empty role.";
            else roles.Add( role );
        }
        return error == null ? new PartyDescription( url, apps.ToImmutable(), roles ) : null;
    }
}
