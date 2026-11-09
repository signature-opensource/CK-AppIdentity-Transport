using CK.Core;
using NUnit.Framework;
using Shouldly;
using System;
using System.Security.Cryptography;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.AuthCenter.Tests;

[TestFixture]
public class FieldEncryptionTests
{
    static readonly NormalizedPath _center = "Test/$Center/#Dev";
    static readonly NormalizedPath _front = "Test/$Front/#Dev";

    [Test]
    public void a_field_is_bound_to_its_key_context_and_time()
    {
        using var key = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        var spki = key.ExportSubjectPublicKeyInfo();
        var id = CK.AppIdentity.KeyManagement.PartyEncryption.GetKeyId( spki );
        ECDiffieHellman? Find( byte[] keyId ) => keyId.AsSpan().SequenceEqual( id ) ? key : null;
        var context = AuthCenterFieldEncryption.GetContext( _center, _front, "CK.IO.Authentication.Basic.IBasicLoginCommand", "Password" );
        var utcNow = DateTime.UtcNow;

        var cipher = AuthCenterFieldEncryption.Encrypt( spki, "secret", context, utcNow );
        cipher.ShouldStartWith( AuthCenterFieldEncryption.Prefix );
        cipher.ShouldNotContain( "secret" );
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, cipher, Find, context, utcNow, out var clear ).ShouldBeTrue();
        clear.ShouldBe( "secret" );
        AuthCenterFieldEncryption.Encrypt( spki, "secret", context, utcNow ).ShouldNotBe( cipher, "Ephemeral key and nonce: never the same ciphertext." );

        // Another field, command or front.
        foreach( var other in new[] { AuthCenterFieldEncryption.GetContext( _center, _front, "CK.IO.Authentication.Basic.IBasicLoginCommand", "UserName" ),
                                      AuthCenterFieldEncryption.GetContext( _center, _front, "Other.Command", "Password" ),
                                      AuthCenterFieldEncryption.GetContext( _center, "Test/$Other/#Dev", "CK.IO.Authentication.Basic.IBasicLoginCommand", "Password" ) } )
        {
            AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, cipher, Find, other, utcNow, out _ ).ShouldBeFalse();
        }
        // Out of the freshness window.
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, cipher, Find, context, utcNow + AuthCenterFieldEncryption.Freshness + TimeSpan.FromSeconds( 1 ), out _ ).ShouldBeFalse();
        // Another key, an unknown key, an altered ciphertext, a clear value, garbage.
        using var otherKey = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, cipher, _ => otherKey, context, utcNow, out _ ).ShouldBeFalse();
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, cipher, _ => null, context, utcNow, out _ ).ShouldBeFalse();
        var bytes = System.Buffers.Text.Base64Url.DecodeFromChars( cipher.AsSpan( AuthCenterFieldEncryption.Prefix.Length ) );
        bytes[^1] ^= 1;
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, AuthCenterFieldEncryption.Prefix + System.Buffers.Text.Base64Url.EncodeToString( bytes ), Find, context, utcNow, out _ ).ShouldBeFalse();
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, "secret", Find, context, utcNow, out _ ).ShouldBeFalse();
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, AuthCenterFieldEncryption.Prefix + "!!", Find, context, utcNow, out _ ).ShouldBeFalse();
        AuthCenterFieldEncryption.TryDecrypt( TestHelper.Monitor, AuthCenterFieldEncryption.Prefix + "AAAA", Find, context, utcNow, out _ ).ShouldBeFalse();
    }
}

[TestFixture]
public class EncryptionKeysTests
{
    [Test]
    public async System.Threading.Tasks.Task the_encryption_keys_rotate_and_survive_a_restart_Async()
    {
        byte[] Id( CK.AppIdentity.PartyEncryptionKey k ) => CK.AppIdentity.KeyManagement.PartyEncryption.GetKeyId( k.PublicKey.Span );
        // The test store persists between runs: working 3 days ahead, every key of a previous run is expired (and pruned).
        var utcNow = DateTime.UtcNow.AddDays( 3 );
        CK.AppIdentity.PartyEncryptionKey first;
        NormalizedPath folder;
        await using( var app = await AuthCenterApp.StartAsync() )
        {
            folder = app.Identity.LocalFileStore.FolderPath.Combine( "KeyManagement/EncryptionKeys" );
            var keys = app.Identity.GetRequiredFeature<CK.AppIdentity.KeyManagement.ILocalKeys>();
            first = keys.GetEncryptionKey( utcNow );
            keys.GetEncryptionKey( utcNow.AddHours( 1 ) ).ShouldBe( first, "Published for a day." );

            // Near its end, a new key is published; the previous one still decrypts during the overlap.
            var later = utcNow + CK.AppIdentity.KeyManagement.PartyEncryption.KeyLifetime - CK.AppIdentity.KeyManagement.PartyEncryption.KeyOverlap;
            var second = keys.GetEncryptionKey( later );
            second.ShouldNotBe( first );
            keys.FindEncryptionKey( Id( first ), later ).ShouldNotBeNull();
            keys.FindEncryptionKey( Id( first ), utcNow + CK.AppIdentity.KeyManagement.PartyEncryption.KeyLifetime + CK.AppIdentity.KeyManagement.PartyEncryption.KeyOverlap ).ShouldBeNull( "Past its overlap." );
            keys.FindEncryptionKey( Id( second ), later ).ShouldNotBeNull();
        }
        // The keys are persisted (protected) in the local file store.
        await using( var app = await AuthCenterApp.StartAsync() )
        {
            app.Identity.GetRequiredFeature<CK.AppIdentity.KeyManagement.ILocalKeys>().FindEncryptionKey( Id( first ), utcNow ).ShouldNotBeNull();
        }
        // These keys are in the future: the other tests must not use them.
        System.IO.Directory.Delete( folder, recursive: true );
    }

    [Test]
    public async System.Threading.Tasks.Task only_an_invalid_key_file_is_deleted_Async()
    {
        byte[] Id( CK.AppIdentity.PartyEncryptionKey k ) => CK.AppIdentity.KeyManagement.PartyEncryption.GetKeyId( k.PublicKey.Span );
        static CK.AppIdentity.KeyManagement.ILocalKeys Keys( AuthCenterApp app ) => app.Identity.GetRequiredFeature<CK.AppIdentity.KeyManagement.ILocalKeys>();
        var utcNow = DateTime.UtcNow.AddDays( 3 );
        CK.AppIdentity.PartyEncryptionKey published;
        NormalizedPath folder;
        await using( var app = await AuthCenterApp.StartAsync() )
        {
            folder = app.Identity.LocalFileStore.FolderPath.Combine( "KeyManagement/EncryptionKeys" );
            published = Keys( app ).GetEncryptionKey( utcNow );
        }
        // The key published at the start (now) has been pruned by the one 3 days ahead.
        var keyFile = System.IO.Directory.GetFiles( folder ).ShouldHaveSingleItem();
        try
        {
            // A key file that can't be read (here, opened exclusively by another process) is not used, but it is kept:
            // deleting it would lose the data it encrypts.
            using( System.IO.File.Open( keyFile, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.None ) )
            {
                await using var app = await AuthCenterApp.StartAsync();
                Keys( app ).FindEncryptionKey( Id( published ), utcNow ).ShouldBeNull();
            }
            System.IO.File.Exists( keyFile ).ShouldBeTrue( "A key that can't be read is kept." );
            await using( var app = await AuthCenterApp.StartAsync() )
            {
                Keys( app ).FindEncryptionKey( Id( published ), utcNow ).ShouldNotBeNull( "Once readable, it is used." );
            }
            // An invalid key file is deleted.
            System.IO.File.WriteAllBytes( keyFile, [1, 2, 3] );
            await using( var app = await AuthCenterApp.StartAsync() )
            {
                Keys( app ).FindEncryptionKey( Id( published ), utcNow ).ShouldBeNull();
            }
            System.IO.File.Exists( keyFile ).ShouldBeFalse( "An invalid key is deleted." );
        }
        finally
        {
            // These keys are in the future: the other tests must not use them.
            System.IO.Directory.Delete( folder, recursive: true );
        }
    }
}
