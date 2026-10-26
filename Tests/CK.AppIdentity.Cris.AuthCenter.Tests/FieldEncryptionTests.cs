using CK.Core;
using NUnit.Framework;
using Shouldly;
using System;
using System.Security.Cryptography;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

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
        var id = AuthCenterFieldEncryption.GetKeyId( spki );
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
        byte[] Id( string publicKey ) => AuthCenterFieldEncryption.GetKeyId( System.Buffers.Text.Base64Url.DecodeFromChars( publicKey ) );
        // The test store persists between runs: working 3 days ahead, every key of a previous run is expired (and pruned).
        var utcNow = DateTime.UtcNow.AddDays( 3 );
        string first;
        NormalizedPath folder;
        await using( var app = await AuthCenterApp.StartAsync() )
        {
            folder = app.Identity.LocalFileStore.FolderPath.Combine( "AuthCenter/EncryptionKeys" );
            var local = app.LocalCenter;
            var signer = app.Identity.GetRequiredFeature<CK.AppIdentity.KeyManagement.ILocalKeys>();
            var keys = local.EncryptionKeys;
            first = keys.GetPublished( TestHelper.Monitor, signer, utcNow ).PublicKey;
            keys.GetPublished( TestHelper.Monitor, signer, utcNow.AddHours( 1 ) ).PublicKey.ShouldBe( first, "Published for a day." );

            // Near its end, a new key is published; the previous one still decrypts during the grace.
            var later = utcNow + AuthCenterEncryptionKeys.Lifetime - AuthCenterEncryptionKeys.Grace;
            var second = keys.GetPublished( TestHelper.Monitor, signer, later ).PublicKey;
            second.ShouldNotBe( first );
            keys.Find( Id( first ), later ).ShouldNotBeNull();
            keys.Find( Id( first ), utcNow + AuthCenterEncryptionKeys.Lifetime + AuthCenterEncryptionKeys.Grace ).ShouldBeNull( "Past its grace." );
            keys.Find( Id( second ), later ).ShouldNotBeNull();
        }
        // The keys are persisted (protected) in the local file store.
        await using( var app = await AuthCenterApp.StartAsync() )
        {
            app.LocalCenter.EncryptionKeys.Find( Id( first ), utcNow ).ShouldNotBeNull();
        }
        // These keys are in the future: the other tests must not use them.
        System.IO.Directory.Delete( folder, recursive: true );
    }
}
