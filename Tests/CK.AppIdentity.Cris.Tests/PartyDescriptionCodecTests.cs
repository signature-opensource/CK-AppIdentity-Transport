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
                                                              [new ClientApplicationDescription( "App", "/", ClientApplicationDescription.FactContext.FindOrCreate( "Enlistment|Other" ) ),
                                                               new ClientApplicationDescription( "Admin", "/admin" )],
                                                              ["Manager", "Operator"],
                                                              [new( "Region", "eu-west" )],
                                                              [new( "Enlistment", new PartyRoute( "https://admin.example.com/admin/app-identity/enlist", ["Test/$Front/#Dev", "Test/$Admin/#Dev"] ) ),
                                                               new( "Other", PartyRoute.Hosted( "Some.Command", "Test/$Front/#Dev" ) )],
                                                              new PartyEncryptionKey( [1, 2, 3, 4], [5, 6, 7] ) );

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
        w.WriteString( "Enlistment" );
        w.WriteString( "a newer field of the client" );
        w.EndBlock( c );
        w.WriteInt32( 1 );
        w.WriteString( "Manager" );
        w.WriteInt32( 0 ); // No data announcement.
        w.WriteInt32( 0 ); // No route.
        w.WriteBool( false ); // No encryption key.
        w.WriteString( "a newer section of the description" );
        w.EndBlock( d );
        w.WriteByte( 42 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        var description = PartyDescriptionCodec.Read( ref r, out var error );
        error.ShouldBeNull();
        description.ShouldBe( new PartyDescription( new Uri( "https://front.example.com" ),
                                                    [new ClientApplicationDescription( "App", "/", ClientApplicationDescription.FactContext.FindOrCreate( "Enlistment" ) )],
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
}
