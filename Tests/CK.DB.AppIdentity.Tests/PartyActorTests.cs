using CK.Core;
using CK.DB.Actor;
using CK.SqlServer;
using CK.Testing;
using Dapper;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.AppIdentity.Tests;

public class PartyActorTests
{
    static PartyActorTable Table => SharedEngine.Map.StObjs.Obtain<PartyActorTable>().ShouldNotBeNull();

    static string NewFullName() => $"Test/Domain/$P{Guid.NewGuid():N}/#Dev";

    [Test]
    public async Task anonymous_cannot_ensure_party_actors_Async()
    {
        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        await Should.ThrowAsync<SqlDetailedException>( () => Table.EnsureAsync( context, 0, NewFullName() ) );
    }

    [Test]
    public async Task empty_full_name_is_rejected_Async()
    {
        // The empty FullName is the one of the PartyActor 0.
        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        await Should.ThrowAsync<SqlDetailedException>( () => Table.EnsureAsync( context, 1, "" ) );
    }

    [Test]
    public async Task ensure_creates_then_finds_the_party_actor_Async()
    {
        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        var fullName = NewFullName();
        var id = await Table.EnsureAsync( context, 1, fullName );
        id.ShouldBeGreaterThan( 0 );
        (await Table.EnsureAsync( context, 1, fullName )).ShouldBe( id );

        context[Table].QuerySingle<string>( "select FullName from CK.vPartyActor where PartyActorId = @id", new { id } )
                      .ShouldBe( fullName );
    }

    [Test]
    public async Task full_name_is_case_insensitive_Async()
    {
        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        var fullName = NewFullName();
        var id = await Table.EnsureAsync( context, 1, fullName );
        (await Table.EnsureAsync( context, 1, fullName.ToUpperInvariant() )).ShouldBe( id );
        (await Table.EnsureAsync( context, 1, fullName.ToLowerInvariant() )).ShouldBe( id );

        // The first casing is kept.
        context[Table].QuerySingle<string>( "select FullName from CK.tPartyActor where PartyActorId = @id", new { id } )
                      .ShouldBe( fullName );
    }

    [Test]
    public async Task full_name_max_length_is_supported_Async()
    {
        var fullName = $"{new string( 'D', CoreApplicationIdentity.DomainNameMaxLength - 32 )}{Guid.NewGuid():N}"
                       + $"/${new string( 'P', CoreApplicationIdentity.PartyNameMaxLength )}"
                       + $"/#{new string( 'E', CoreApplicationIdentity.EnvironmentNameMaxLength - 1 )}";
        fullName.Length.ShouldBe( CoreApplicationIdentity.FullNameMaxLength );
        CoreApplicationIdentity.TryParseFullName( fullName, out _, out _, out _ ).ShouldBeTrue();

        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        var id = await Table.EnsureAsync( context, 1, fullName );
        context[Table].QuerySingle<string>( "select FullName from CK.tPartyActor where PartyActorId = @id", new { id } )
                      .ShouldBe( fullName );
    }

    [Test]
    public async Task concurrent_ensures_of_the_same_full_name_return_the_same_party_actor_Async()
    {
        // Initializes the test helpers and the engine before the concurrent calls (their lazy initialization is not thread safe).
        // Monitors are not thread safe: each call uses its own.
        var table = Table;
        var fullName = NewFullName();
        var ids = await Task.WhenAll( Enumerable.Range( 0, 20 ).Select( _ => Task.Run( async () =>
        {
            using var context = new SqlStandardCallContext( new ActivityMonitor() );
            return await table.EnsureAsync( context, 1, fullName );
        } ) ) );
        ids.Distinct().Count().ShouldBe( 1 );
        ids[0].ShouldBeGreaterThan( 0 );
    }

    [Test]
    public async Task can_destroy_party_actor_even_when_it_belongs_to_groups_Async()
    {
        var groupTable = SharedEngine.Map.StObjs.Obtain<GroupTable>().ShouldNotBeNull();
        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        var fullName = NewFullName();
        var id = await Table.EnsureAsync( context, 1, fullName );
        var groupId = await groupTable.CreateGroupAsync( context, 1 );
        await groupTable.AddMemberAsync( context, 1, groupId, id );

        context[Table].QuerySingle<string>( "select MemberType from CK.vGroupMember where GroupId = @groupId and MemberId = @id", new { groupId, id } )
                      .ShouldBe( "PartyActor" );
        context[Table].QuerySingle<string>( "select MemberName from CK.vGroupMember where GroupId = @groupId and MemberId = @id", new { groupId, id } )
                      .ShouldBe( fullName );

        await Table.DestroyAsync( context, 1, id );

        context[Table].QuerySingle<int>( "select count(*) from CK.tActor where ActorId = @id", new { id } ).ShouldBe( 0 );
        context[Table].QuerySingle<int>( "select count(*) from CK.tPartyActor where PartyActorId = @id", new { id } ).ShouldBe( 0 );
        context[Table].QuerySingle<int>( "select count(*) from CK.tActorProfile where ActorId = @id", new { id } ).ShouldBe( 0 );

        // Destroying an unexisting PartyActor does nothing.
        await Table.DestroyAsync( context, 1, id );

        // The FullName can be reused: this is a new PartyActor.
        (await Table.EnsureAsync( context, 1, fullName )).ShouldNotBe( id );
    }

    [Test]
    public async Task party_actor_0_cannot_be_destroyed_Async()
    {
        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        await Should.ThrowAsync<SqlDetailedException>( () => Table.DestroyAsync( context, 1, 0 ) );
    }
}
