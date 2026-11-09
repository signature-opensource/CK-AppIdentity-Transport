using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

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
///     count, then [client] per client application: its name, its request path, its facts
///     count, the roles
///     count, then the data announcements: name, value
///     count, then the routes: name, target, count, the full names of the path
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
            // Its facts (a CKTrait): added at the end of the block, an older reader skips them.
            w.WriteString( a.Facts.ToString() );
            w.EndBlock( c );
        }
        w.WriteInt32( description.Roles.Length );
        foreach( var role in description.Roles ) w.WriteString( role );
        // The data announcements and the routes: added at the end of the block, an older reader skips them.
        w.WriteInt32( description.Data.Count );
        foreach( var (name, value) in description.Data )
        {
            w.WriteString( name );
            w.WriteString( value );
        }
        w.WriteInt32( description.Routes.Count );
        foreach( var (name, route) in description.Routes )
        {
            w.WriteString( name );
            w.WriteString( route.Target );
            w.WriteInt32( route.Path.Length );
            foreach( var p in route.Path ) w.WriteString( p );
        }
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
            // An older writer doesn't write the facts.
            var facts = c.IsEnd ? null : ClientApplicationDescription.FactContext.FindOrCreate( c.ReadString() );
            if( name.Length == 0 || !path.StartsWith( '/' ) ) error ??= $"Invalid client application '{name}' ('{path}').";
            else apps.Add( new ClientApplicationDescription( name, path, facts ) );
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
        // An older writer doesn't write the data announcements nor the routes.
        var data = new List<KeyValuePair<string, string>>();
        if( !d.IsEnd )
        {
            int dataCount = d.ReadInt32();
            Throw.CheckData( "Invalid data count.", dataCount >= 0 );
            for( int i = 0; i < dataCount; ++i )
            {
                var name = d.ReadString();
                var value = d.ReadString();
                if( !PartyDescription.IsValidName( name ) ) error ??= $"Invalid data announcement name '{name}'.";
                else data.Add( new KeyValuePair<string, string>( name, value ) );
            }
        }
        var routes = new List<KeyValuePair<string, PartyRoute>>();
        if( !d.IsEnd )
        {
            int routeCount = d.ReadInt32();
            Throw.CheckData( "Invalid route count.", routeCount >= 0 );
            for( int i = 0; i < routeCount; ++i )
            {
                var name = d.ReadString();
                var target = d.ReadString();
                int pathLength = d.ReadInt32();
                Throw.CheckData( "Invalid route length.", pathLength >= 0 && pathLength <= PartyRoute.MaxLength );
                var path = new string[pathLength];
                for( int j = 0; j < pathLength; ++j ) path[j] = d.ReadString();
                if( !PartyDescription.IsValidName( name ) )
                {
                    error ??= $"Invalid route name '{name}'.";
                }
                else if( pathLength == 0 || path.Any( string.IsNullOrWhiteSpace ) || path.Distinct( StringComparer.Ordinal ).Count() != pathLength )
                {
                    error ??= $"Invalid path of the route '{name}': 1 to {PartyRoute.MaxLength} distinct full names are expected.";
                }
                else
                {
                    routes.Add( new KeyValuePair<string, PartyRoute>( name, new PartyRoute( target, path ) ) );
                }
            }
        }
        return error == null ? new PartyDescription( url, apps.ToImmutable(), roles, data, routes ) : null;
    }
}
