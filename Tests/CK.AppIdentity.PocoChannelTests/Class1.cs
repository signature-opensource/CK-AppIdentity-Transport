using FluentAssertions;
using NUnit.Framework;
using System.IO;

namespace CK.AppIdentity.PocoChannelTests
{
    [TestFixture]
    public class BasicTests
    {
        [Test]
        public void Max_PrefixLength_is_between_1_and_9_bytes()
        {
            using var m = new MemoryStream();
            var w = new BinaryWriter( m );

            w.Write7BitEncodedInt64( 127 );
            m.Position.Should().Be( 1 );

            m.Position = 0;
            w.Write7BitEncodedInt64( long.MaxValue );
            m.Position.Should().Be( 9 );

        }
    }
}
