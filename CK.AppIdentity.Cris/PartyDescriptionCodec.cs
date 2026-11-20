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
///     count, then [client] per client application: its name, its request path, count, then its facts: key, value
///     count, the roles
///     count, then the data announcements: name, value
///     count, then the routes (one per name and host): name, hasTarget, the target, count, the full names of the path
///     hasEncryptionKey, the public key and the signature (each one: its length, its bytes)
///     count, then the collected items per route name: name, count, then per item: value, count, the full names of the path
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
            // Its facts: (key, value) pairs.
            var facts = a.Facts.Pairs.ToList();
            w.WriteInt32( facts.Count );
            foreach( var (factKey, factValue) in facts )
            {
                w.WriteString( factKey );
                w.WriteString( factValue );
            }
            w.EndBlock( c );
        }
        w.WriteInt32( description.Roles.Length );
        foreach( var role in description.Roles ) w.WriteString( role );
        // The data announcements: added at the end of the block, an older reader skips them.
        w.WriteInt32( description.Data.Count );
        foreach( var (name, value) in description.Data )
        {
            w.WriteString( name );
            w.WriteString( value );
        }
        // The encryption key: added at the end of the block, an older reader skips it.
        var key = description.EncryptionKey;
        w.WriteBool( key != null );
        if( key != null )
        {
            w.WriteSmallUInt32( (uint)key.PublicKey.Length );
            w.WriteBytes( key.PublicKey.Span );
            w.WriteSmallUInt32( (uint)key.Signature.Length );
            w.WriteBytes( key.Signature.Span );
        }
        w.EndBlock( d );
    }

    /// <summary>
    /// The maximal length of the public key and of the signature of an encryption key.
    /// </summary>
    public const int MaxEncryptionKeyLength = 8192;

    /// <summary>
    /// The maximal number of facts of a client application.
    /// </summary>
    public const int MaxFactCount = 256;

    /// <summary>
    /// Reads a description written by <see cref="Write(ref FastByteWriter, PartyDescription)"/>. The reader is always
    /// moved after the description's block, even when the description is invalid: an invalid content of the block (a
    /// negative or too big count, a truncated field) is an <paramref name="error"/>, never an exception. Only an invalid
    /// block length throws an <see cref="System.IO.InvalidDataException"/>.
    /// </summary>
    /// <param name="r">The reader.</param>
    /// <param name="error">The reason why the description is invalid.</param>
    /// <returns>The description, or null when it is invalid (see <paramref name="error"/>).</returns>
    public static PartyDescription? Read( ref FastByteReader r, out string? error )
    {
        var d = r.ReadBlock();
        try
        {
            return ReadContent( ref d, out error );
        }
        catch( Exception ex ) when ( ex is System.IO.InvalidDataException or ArgumentException or OverflowException )
        {
            error = $"Invalid description block: {ex.Message}";
            return null;
        }
    }

    static PartyDescription? ReadContent( ref FastByteReader d, out string? error )
    {
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
            // A block without facts (they are the last field) has none.
            int factCount = c.IsEnd ? 0 : c.ReadInt32();
            Throw.CheckData( "Invalid fact count.", factCount >= 0 && factCount <= MaxFactCount );
            var pairs = new List<KeyValuePair<string, string>>( factCount );
            for( int j = 0; j < factCount; ++j )
            {
                var key = c.ReadString();
                pairs.Add( new KeyValuePair<string, string>( key, c.ReadString() ) );
            }
            if( name.Length == 0 || !path.StartsWith( '/' ) ) error ??= $"Invalid client application '{name}' ('{path}').";
            else if( !ClientApplicationFacts.TryCreate( pairs, out var facts, out var factError ) ) error ??= $"Invalid facts of the client application '{name}': {factError}";
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
        // An older writer doesn't write the encryption key.
        PartyEncryptionKey? encryptionKey = null;
        if( !d.IsEnd && d.ReadBool() )
        {
            var publicKey = ReadKeyBytes( ref d );
            var signature = ReadKeyBytes( ref d );
            if( publicKey.Length == 0 || signature.Length == 0 ) error ??= "Invalid empty encryption key.";
            else encryptionKey = new PartyEncryptionKey( publicKey, signature );
        }
        return error == null
                ? new PartyDescription( url,
                                        apps.ToImmutable(),
                                        roles,
                                        data,
                                        encryptionKey )
                : null;

        static byte[] ReadKeyBytes( ref FastByteReader r )
        {
            var length = r.ReadSmallUInt32();
            Throw.CheckData( "Invalid encryption key length.", length <= MaxEncryptionKeyLength );
            return r.ReadBytes( length );
        }
    }
}
