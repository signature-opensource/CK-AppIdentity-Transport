using CK.Core;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The description of a party (its public URL and its client applications) is announced to the remote with the accepted
/// commands, on each connection and again when it changes.
/// </summary>
[TestFixture]
public class DescriptionAnnouncementTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 10 );

    /// <summary>
    /// The listener's contribution: a client application, and a public URL that the test changes.
    /// </summary>
    public sealed class TestDescriptionFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public static Uri? PublicUrl;

        public TestDescriptionFeatureDriver( ApplicationIdentityService s ) : base( s, true ) { }

        public Task ChangeAsync( Uri publicUrl )
        {
            PublicUrl = publicUrl;
            return OnDescriptionChangedAsync( TestHelper.Monitor, ApplicationIdentityService );
        }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
        {
            builder.PublicUrl ??= PublicUrl;
            builder.AddClientApplication( "App", "/" );
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

    static async Task<PartyDescription> WaitForAsync( IRemoteParty remote, Func<PartyDescription, bool> condition )
    {
        for( int i = 0; i < 100; ++i )
        {
            if( condition( remote.Description ) ) return remote.Description;
            await Task.Delay( 100 );
        }
        return remote.Description;
    }

    [Test]
    public async Task the_parties_announce_their_description_to_each_other_and_again_when_it_changes_Async()
    {
        TestDescriptionFeatureDriver.PublicUrl = new Uri( "https://listener.example.com" );
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         c => c["Local:PublicUrl"] = "https://sender.example.com",
                                                                         [],
                                                                         null,
                                                                         [typeof( TestDescriptionFeatureDriver )] );
        var (sender, listener) = pair;
        (await sender.CrisChannel.WaitForAcceptedCommandsAsync( _timeout )).ShouldBeTrue();
        var senderOnListener = listener.ApplicationIdentityService.Remotes.Single();
        (await senderOnListener.GetRequiredFeature<CrisChannelFeature>().WaitForAcceptedCommandsAsync( _timeout )).ShouldBeTrue();

        // Each side knows the other's description (announced with the accepted commands).
        var listenerOnSender = sender.ApplicationIdentityService.Remotes.Single();
        listenerOnSender.Description.GetClientApplicationUrl().ShouldBe( "https://listener.example.com" );
        senderOnListener.Description.PublicUrl.ShouldBe( new Uri( "https://sender.example.com" ) );
        senderOnListener.Description.ClientApplications.ShouldBeEmpty();

        // The listener's contribution changes (like the URL of an HTTP endpoint known once the host has started): it is
        // announced again.
        await listener.Services.GetRequiredService<TestDescriptionFeatureDriver>().ChangeAsync( new Uri( "https://other-listener.example.com" ) );
        var d = await WaitForAsync( listenerOnSender, d => d.PublicUrl?.Host == "other-listener.example.com" );
        d.GetClientApplicationUrl().ShouldBe( "https://other-listener.example.com" );
    }
}
