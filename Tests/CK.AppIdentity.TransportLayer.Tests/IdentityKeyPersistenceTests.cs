using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.DataProtection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Covers the identity round-trip across restarts.
/// <para>
/// Easily left unexercised: the creation path never reads back from disk, and a
/// <see cref="IDataProtector"/> test double that is the identity function (<see cref="FakeProtector"/>)
/// makes a Protect/Unprotect mismatch cancel itself out. Under a protector that actually protects
/// (<see cref="HeaderProtector"/>), such a mismatch makes the current key unreadable on every start.
/// </para>
/// </summary>
[TestFixture]
public class IdentityKeyPersistenceTests
{
    sealed record Snapshot( string[] KeyNames, string[] Events, byte[] Certificate );

    static Snapshot Take( string partyName )
        => new( IdentityStoreHelper.GetKeyNames( partyName ),
                IdentityStoreHelper.GetEventFiles( partyName ),
                File.ReadAllBytes( IdentityStoreHelper.GetCurrentCertificatePath( partyName ) ) );

    static async Task CheckSurvivesRestartsAsync( string partyName, IDataProtectionProvider protector, CancellationToken token )
    {
        IdentityStoreHelper.ClearKeys( partyName );

        // First start: no identity exists, one is created: the current key, the next one, the inception.
        await using( await IdentityStoreHelper.CreateAsync( partyName, protector, token ) ) { }
        var first = Take( partyName );
        first.KeyNames.ShouldBe( new[] { "0", "1", "recovery-0" }, "The first start creates the current key and the committed next one." );
        first.Events.ShouldBe( new[] { "0.event" } );

        // Second start over the same store: everything must be READ BACK, nothing recreated.
        await using( await IdentityStoreHelper.CreateAsync( partyName, protector, token ) ) { }
        var second = Take( partyName );
        second.KeyNames.ShouldBe( first.KeyNames );
        second.Events.ShouldBe( first.Events );
        second.Certificate.ShouldBe( first.Certificate,
            "The certificate is re-minted only when it does not match the current key: a restart must not touch it." );

        // And a third one, to be sure nothing accumulates either.
        await using( await IdentityStoreHelper.CreateAsync( partyName, protector, token ) ) { }
        Take( partyName ).ShouldBeEquivalentTo( second );
    }

    [CancelAfter( 20000 )]
    [Test]
    public Task Identity_keys_survive_a_restart_with_a_real_protector_Async( CancellationToken token )
        => CheckSurvivesRestartsAsync( "KeyPersistReal", new HeaderProtector(), token );

    [CancelAfter( 20000 )]
    [Test]
    public Task Identity_keys_survive_a_restart_with_the_FakeProtector_Async( CancellationToken token )
        => CheckSurvivesRestartsAsync( "KeyPersistFake", FakeProtector.Fake, token );

    [Test]
    public void HeaderProtector_round_trips_and_rejects_foreign_payloads()
    {
        var p = new HeaderProtector();
        var clear = new byte[] { 1, 2, 3, 4, 5 };
        p.Unprotect( p.Protect( clear ) ).ShouldBe( clear );
        // A mismatched Protect/Unprotect overload pairing hands back something this protector never
        // produced: that must throw, not silently return garbage.
        Should.Throw<System.Security.Cryptography.CryptographicException>( () => p.Unprotect( clear ) );
    }

    [CancelAfter( 20000 )]
    [Test]
    public async Task The_stored_key_is_protected_Async( CancellationToken token )
    {
        // The default store must actually go through the protector: the file is not the clear PKCS#8.
        const string partyName = "KeyProtected";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            using var key = IdentityStoreHelper.OpenKey( s, protector, 0 );
            var privateScalar = key.ExportParameters( includePrivateParameters: true ).D!;
            var stored = File.ReadAllBytes( IdentityStoreHelper.GetCoreKeysFolder( partyName ).AppendPart( "0.key" ) );
            stored.AsSpan().IndexOf( privateScalar ).ShouldBe( -1, "The private key must not be stored in clear." );
            protector.Unprotect( stored ).AsSpan().IndexOf( privateScalar ).ShouldBeGreaterThanOrEqualTo( 0,
                "What is stored is the key, through the protector." );
        }
    }
}
