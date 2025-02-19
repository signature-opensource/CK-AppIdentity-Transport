using FluentAssertions;
using NUnit.Framework;
using System.Buffers;

namespace CK.AppIdentity.TransportLayer.Tests;

[TestFixture]
public class MutableSequenceTests
{
    [Test]
    public void adding_external_memory()
    {
        var b = new MutableSequence<byte>();
        var prefix = b.GetSpan( 3 );
        prefix[0] = 1;
        prefix[1] = 2;
        prefix[2] = 3;
        b.Length.Should().Be( 0 );
        b.Advance( 3 );
        b.Length.Should().Be( 3 );
        b.AddSegment( new byte[] { 4 } );
        b.Length.Should().Be( 4 );
        var s = b.GetReadOnlySequence();
        s.ToArray().Should().BeEquivalentTo( new byte[] { 1, 2, 3, 4 } );
    }
}
