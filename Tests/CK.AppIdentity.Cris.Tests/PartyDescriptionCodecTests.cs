using CK.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.Collections.Immutable;

namespace CK.AppIdentity.Cris.Tests;

[TestFixture]
public class PartyDescriptionCodecTests
{
    static PartyDescription Sample() => new PartyDescription( new Uri( "https://front.example.com" ),
                                                              [new ClientApplicationDescription( "App", "/", ClientApplicationFacts.Create( ("Enlistment", "app-identity/enlist"), ("Other", ""), ("Other", "x") ) ),
                                                               new ClientApplicationDescription( "Admin", "/admin" )],
                                                              ["Manager", "Operator"],
                                                              [new( "Region", "eu-west" )],
                                                              [new( "Enlistment", [new PartyRoute( "https://admin.example.com/admin/app-identity/enlist", ["Test/$Front/#Dev", "Test/$Admin/#Dev"] )] ),
                                                               new( "Mail", [PartyRoute.Hosted( null, "Test/$Front/#Dev" ), new PartyRoute( null, ["Test/$Front/#Dev", "Test/$Mail2/#Dev"] )] )],
                                                              new PartyEncryptionKey( [1, 2, 3, 4], [5, 6, 7] ),
                                                              [new( "Enlistment", [CollectedItem.Own( "{\"Party\":\"X\"}", "Test/$Front/#Dev" ),
                                                                                   new CollectedItem( "{\"Party\":\"Y\"}", ["Test/$Worker/#Dev", "Test/$Front/#Dev"] )] )] );

    [Test]
    public void a_description_round_trips()
    {
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        PartyDescriptionCodec.Write( ref w, Sample() );
        PartyDescriptionCodec.Write( ref w, PartyDescription.Empty );
        w.WriteByte( 42 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        var d = PartyDescriptionCodec.Read( ref r, out var error );
        error.ShouldBeNull();
        d.ShouldBe( Sample() );
        PartyDescriptionCodec.Read( ref r, out error ).ShouldBe( PartyDescription.Empty );
        error.ShouldBeNull();
        r.ReadByte().ShouldBe( (byte)42 );
    }

    [Test]
    public void the_fields_of_a_newer_writer_are_skipped()
    {
        // A newer writer adds a field to each client application (after its facts) and a section at the end of the description.
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        var d = w.BeginBlock();
        w.WriteBool( true );
        w.WriteString( "https://front.example.com/" );
        w.WriteInt32( 1 );
        var c = w.BeginBlock();
        w.WriteString( "App" );
        w.WriteString( "/" );
        w.WriteInt32( 1 );
        w.WriteString( "Enlistment" );
        w.WriteString( "app-identity/enlist" );
        w.WriteString( "a newer field of the client" );
        w.EndBlock( c );
        w.WriteInt32( 1 );
        w.WriteString( "Manager" );
        w.WriteInt32( 0 ); // No data announcement.
        w.WriteInt32( 0 ); // No route.
        w.WriteBool( false ); // No encryption key.
        w.WriteInt32( 0 ); // No collected item.
        w.WriteString( "a newer section of the description" );
        w.EndBlock( d );
        w.WriteByte( 42 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        var description = PartyDescriptionCodec.Read( ref r, out var error );
        error.ShouldBeNull();
        description.ShouldBe( new PartyDescription( new Uri( "https://front.example.com" ),
                                                    [new ClientApplicationDescription( "App", "/", ClientApplicationFacts.Create( ("Enlistment", "app-identity/enlist") ) )],
                                                    ["Manager"] ) );
        r.ReadByte().ShouldBe( (byte)42 );
    }

    [Test]
    public void a_client_application_of_an_older_writer_has_no_fact()
    {
        // An older writer doesn't write the facts of its client applications.
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        var d = w.BeginBlock();
        w.WriteBool( false );
        w.WriteInt32( 1 );
        var c = w.BeginBlock();
        w.WriteString( "App" );
        w.WriteString( "/" );
        w.EndBlock( c );
        w.WriteInt32( 0 );
        w.EndBlock( d );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        var description = PartyDescriptionCodec.Read( ref r, out var error );
        error.ShouldBeNull();
        description.ShouldNotBeNull().ClientApplications.ShouldHaveSingleItem().Facts.IsEmpty.ShouldBeTrue();
    }

    [Test]
    public void an_invalid_description_is_null_and_is_skipped()
    {
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        var d = w.BeginBlock();
        w.WriteBool( false );
        w.WriteInt32( 1 );
        var c = w.BeginBlock();
        w.WriteString( "App" );
        w.WriteString( "no-leading-slash" );
        w.EndBlock( c );
        w.WriteInt32( 0 );
        w.EndBlock( d );
        w.WriteByte( 42 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        PartyDescriptionCodec.Read( ref r, out var error ).ShouldBeNull();
        error.ShouldBe( "Invalid client application 'App' ('no-leading-slash')." );
        r.ReadByte().ShouldBe( (byte)42 );
    }

    [Test]
    public void an_invalid_collected_item_makes_the_description_invalid()
    {
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        var d = w.BeginBlock();
        w.WriteBool( false );
        w.WriteInt32( 0 ); // No client application.
        w.WriteInt32( 0 ); // No role.
        w.WriteInt32( 0 ); // No data announcement.
        w.WriteInt32( 0 ); // No route.
        w.WriteBool( false ); // No encryption key.
        w.WriteInt32( 1 );
        w.WriteString( "Enlistment" );
        w.WriteInt32( 1 );
        w.WriteString( "V" );
        w.WriteInt32( 3 );
        w.WriteString( "A" );
        w.WriteString( "B" );
        w.WriteString( "A" ); // A loop.
        w.EndBlock( d );
        w.WriteByte( 42 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        PartyDescriptionCodec.Read( ref r, out var error ).ShouldBeNull();
        error.ShouldStartWith( "Invalid item collected for 'Enlistment': " );
        r.ReadByte().ShouldBe( (byte)42 );
    }

    [Test]
    public void an_invalid_count_or_a_truncated_block_is_an_error_not_an_exception()
    {
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        // Too many facts (the reader refuses more than MaxFactCount).
        var d = w.BeginBlock();
        w.WriteBool( false );
        w.WriteInt32( 1 );
        var c = w.BeginBlock();
        w.WriteString( "App" );
        w.WriteString( "/" );
        w.WriteInt32( PartyDescriptionCodec.MaxFactCount + 1 );
        for( int i = 0; i <= PartyDescriptionCodec.MaxFactCount; ++i )
        {
            w.WriteString( $"K{i}" );
            w.WriteString( "V" );
        }
        w.EndBlock( c );
        w.WriteInt32( 0 );
        w.EndBlock( d );
        // A negative role count.
        d = w.BeginBlock();
        w.WriteBool( false );
        w.WriteInt32( 0 );
        w.WriteInt32( -1 );
        w.EndBlock( d );
        // A role count bigger than the block.
        d = w.BeginBlock();
        w.WriteBool( false );
        w.WriteInt32( 0 );
        w.WriteInt32( 1000 );
        w.EndBlock( d );
        w.WriteByte( 42 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        PartyDescriptionCodec.Read( ref r, out var error ).ShouldBeNull();
        error.ShouldNotBeNull().ShouldContain( "Invalid fact count." );
        PartyDescriptionCodec.Read( ref r, out error ).ShouldBeNull();
        error.ShouldNotBeNull().ShouldContain( "Invalid role count." );
        PartyDescriptionCodec.Read( ref r, out error ).ShouldBeNull();
        error.ShouldNotBeNull();
        r.ReadByte().ShouldBe( (byte)42 );
    }

    [Test]
    public void the_names_of_an_advertisement_are_read_from_the_bytes_not_from_their_announced_count()
    {
        // A negative count: the advertisement is invalid.
        using( var sequence = new MutableSequence<byte>() )
        {
            var w = new FastByteWriter( sequence );
            w.WriteInt32( -1 );
            w.Commit();
            var r = new FastByteReader( sequence.GetReadOnlySequence() );
            CrisChannelFeature.Protocol.ReadAccepted( ref r, out _, out _ ).ShouldBeNull();
        }
        // A huge count: nothing is allocated from it, the end of the message is reached.
        using( var sequence = new MutableSequence<byte>() )
        {
            var w = new FastByteWriter( sequence );
            w.WriteInt32( int.MaxValue );
            w.WriteString( "A" );
            w.Commit();
            Should.Throw<System.IO.InvalidDataException>( () =>
            {
                var r = new FastByteReader( sequence.GetReadOnlySequence() );
                CrisChannelFeature.Protocol.ReadAccepted( ref r, out _, out _ );
            } );
        }
        // An invalid description: the names are read, the description is null with its error.
        using( var sequence = new MutableSequence<byte>() )
        {
            var w = new FastByteWriter( sequence );
            w.WriteInt32( 1 );
            w.WriteString( "A" );
            var d = w.BeginBlock();
            w.WriteBool( false );
            w.WriteInt32( -1 );
            w.EndBlock( d );
            w.Commit();
            var r = new FastByteReader( sequence.GetReadOnlySequence() );
            var names = CrisChannelFeature.Protocol.ReadAccepted( ref r, out var description, out var error );
            names.ShouldNotBeNull().ShouldBe( ["A"] );
            description.ShouldBeNull();
            error.ShouldNotBeNull();
        }
    }
}
