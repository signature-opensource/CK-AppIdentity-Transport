using FluentAssertions;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;
using System;
using System.Linq;

namespace CK.AppIdentity.Tests
{
    [TestFixture]
    public class ConfigurationSectionTests
    {
        [Test]
        public void ImmutableConfigurationSection_captures_everything()
        {
            using var config = new ConfigurationManager();
            config["X:A"] = "a";
            config["X:Nothing"] = "";
            config["X:Section"] = "Value for Section";
            config["X:Section:A"] = "a";
            config["X:Section:B"] = null;
            config["X:Section:C:More"] = "C more";

            CheckConfiguration( config.GetSection( "X" ) );
            CheckConfiguration( new ImmutableConfigurationSection( config.GetSection( "X" ) ) );

            static void CheckConfiguration( IConfigurationSection config )
            {
                config["A"].Should().Be( "a" );
                config["Nothing"].Should().Be( "" );
                config["Section"].Should().Be( "Value for Section" );
                config["Section:A"].Should().Be( "a" );
                config["Section:B"].Should().BeNull();
                config["Section:C:More"].Should().Be( "C more" );
                var sA = config.GetSection( "A" );
                sA.Value.Should().Be( "a" );
                sA.GetChildren().Should().BeEmpty();
                var sNothing = config.GetSection( "Nothing" );
                sNothing.Value.Should().Be( "" );
                sNothing.GetChildren().Should().BeEmpty();
                var sSection = config.GetSection( "Section" );
                sSection.Value.Should().Be( "Value for Section" );
                sSection.GetChildren().Should().HaveCount( 3 );
                sSection["A"].Should().Be( "a" );
                sSection["B"].Should().BeNull();
                sSection["C"].Should().BeNull();
                sSection["C:More"].Should().Be( "C more" );
                var sSectionC = sSection.GetSection( "C" );
                var sSectionC2 = config.GetSection( "Section:C" );
                sSectionC.Should().BeEquivalentTo( sSectionC2 );
                config["Section:C:More"].Should().Be( "C more" );
                // Bad key behavior.

                sSection["::::"].Should().BeNull();
                sSection.GetSection( "::::" ).Path.Should().Be( "X:Section:::::" );
                sSection.GetSection( "::::" ).Key.Should().Be( "" );

                sSection[":A"].Should().BeNull();
                sSection.GetSection( ":A" ).Path.Should().Be( "X:Section::A" );
                sSection.GetSection( ":A" ).Key.Should().Be( "A" );

                sSection["A:"].Should().BeNull();
                sSection.GetSection( "A:" ).Path.Should().Be( "X:Section:A:" );
                sSection.GetSection( "A:" ).Key.Should().Be( "" );

                sSection["NO:WAY"].Should().BeNull();
                sSection.GetSection( "NO:WAY" ).Path.Should().Be( "X:Section:NO:WAY" );
                sSection.GetSection( "NO:WAY" ).Key.Should().Be( "WAY" );

                sSection["::NO:WAY::"].Should().BeNull();
                sSection.GetSection( "::NO:WAY::" ).Path.Should().Be( "X:Section:::NO:WAY::" );
                sSection.GetSection( "::NO:WAY::" ).Key.Should().Be( "" );
            }

        }

        [Test]
        public void MutableConfigurationSection_invalid_parameters_check()
        {
            FluentActions.Invoking( () => new MutableConfigurationSection( (IConfigurationSection?)null! ) ).Should().Throw<ArgumentNullException>();
            FluentActions.Invoking( () => new MutableConfigurationSection( (string)null! ) ).Should().Throw<ArgumentNullException>();
            FluentActions.Invoking( () => new MutableConfigurationSection( "" ) ).Should().Throw<ArgumentException>();
            FluentActions.Invoking( () => new MutableConfigurationSection( ":" ) ).Should().Throw<ArgumentException>();
            FluentActions.Invoking( () => new MutableConfigurationSection( "A::B" ) ).Should().Throw<ArgumentException>();
        }

        [Test]
        public void MutableConfigurationSection_tests()
        {
            var c = new MutableConfigurationSection( "X" );
            c["Y"] = "Value";
            c.GetMutableChildren().Should().HaveCount( 1 );
            c.GetMutableChildren().Single().Path.Should().Be( "X:Y" );
            c.GetMutableChildren().Single().Value.Should().Be( "Value" );
            c["Y"].Should().Be( "Value" );

            c["Z:A:B:C"] = "Another Value";
            c["Z:A:B:C"].Should().Be( "Another Value" );
            c.GetRequiredSection( "Z" ).GetRequiredSection( "A" ).GetRequiredSection( "B" ).GetRequiredSection( "C" ).Value.Should().Be( "Another Value" );

            c["Z:A:B"] = "No More C";

            c.GetMutableSection( "Z:A:B:C" ).Exists().Should().BeFalse();
        }
    }
}
