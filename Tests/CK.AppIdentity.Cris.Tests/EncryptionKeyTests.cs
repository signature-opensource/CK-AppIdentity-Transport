using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.Cris;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The encryption key of a party (see <see cref="PartyEncryption"/>): published in its description, verified by its remotes.
/// </summary>
[TestFixture]
public class EncryptionKeyTests
{
    [Test]
    public async Task a_party_publishes_its_encryption_key_and_its_remotes_encrypt_for_it_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor, null, [], null, [] );
        var (sender, listener) = pair;
        {
            (await sender.CrisChannel.WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();
            var published = listener.ApplicationIdentityService.Description.EncryptionKey.ShouldNotBeNull();
            // The sender received it with the listener's description.
            var remote = sender.ApplicationIdentityService.Remotes.Single();
            for( int i = 0; i < 100 && remote.Description.EncryptionKey == null; ++i ) await Task.Delay( 100 );
            remote.Description.EncryptionKey.ShouldBe( published );

            // Signed by the listener: verified with its pinned keys.
            var utcNow = DateTime.UtcNow;
            PartyEncryption.Check( TestHelper.Monitor, remote.GetRequiredFeature<IPartyKeys>(), published, out var spki, out var expiration ).ShouldBe( SignatureVerdict.Valid );
            expiration.ShouldBeGreaterThan( utcNow.AddHours( 23 ), "A key is published for a day." );
            // The key of another party is not the listener's.
            var other = sender.ApplicationIdentityService.Description.EncryptionKey.ShouldNotBeNull();
            PartyEncryption.Check( TestHelper.Monitor, remote.GetRequiredFeature<IPartyKeys>(), other, out _, out _ ).ShouldNotBe( SignatureVerdict.Valid );

            // Encrypted for the listener: only it decrypts, in its context, and its answer is for the sender only.
            var encrypted = PartyEncryption.Encrypt( spki, "secret"u8, "context"u8, utcNow, out var responseKey );
            var keys = listener.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();
            PartyEncryption.TryDecrypt( TestHelper.Monitor, encrypted, id => keys.FindEncryptionKey( id, utcNow ), "another"u8, utcNow, TimeSpan.FromMinutes( 5 ), out _, out _ )
                           .ShouldBeFalse( "Another context." );
            PartyEncryption.TryDecrypt( TestHelper.Monitor, encrypted, id => keys.FindEncryptionKey( id, utcNow ), "context"u8, utcNow.AddMinutes( 10 ), TimeSpan.FromMinutes( 5 ), out _, out _ )
                           .ShouldBeFalse( "Too old." );
            PartyEncryption.TryDecrypt( TestHelper.Monitor, encrypted, id => keys.FindEncryptionKey( id, utcNow ), "context"u8, utcNow, TimeSpan.FromMinutes( 5 ), out var plain, out var listenerResponseKey )
                           .ShouldBeTrue();
            plain.ShouldBe( "secret"u8.ToArray() );
            var answer = PartyEncryption.EncryptResponse( listenerResponseKey!, "answer"u8, "result"u8 );
            PartyEncryption.TryDecryptResponse( TestHelper.Monitor, responseKey, answer, "another"u8, out _ ).ShouldBeFalse();
            PartyEncryption.TryDecryptResponse( TestHelper.Monitor, responseKey, answer, "result"u8, out var back ).ShouldBeTrue();
            back.ShouldBe( "answer"u8.ToArray() );
        }
    }
}
