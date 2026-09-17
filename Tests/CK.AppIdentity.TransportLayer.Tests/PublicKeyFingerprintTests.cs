using CK.AppIdentity.KeyManagement;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests;

[TestFixture]
public class PublicKeyFingerprintTests
{
    [Test]
    public void Fingerprint_is_39_chars_in_8_groups_of_4()
    {
        var f = PublicKeyFingerprint.Compute( new byte[] { 1, 2, 3 } );
        f.Length.ShouldBe( PublicKeyFingerprint.Length );
        f.Length.ShouldBe( 39 );
        var groups = f.Split( '-' );
        groups.Length.ShouldBe( 8 );
        groups.ShouldAllBe( g => g.Length == 4 );
        f.Where( char.IsLetterOrDigit ).Count().ShouldBe( 32 );
    }

    [Test]
    public void Fingerprint_only_uses_the_Base32_alphabet()
    {
        var f = PublicKeyFingerprint.Compute( RandomNumberGenerator.GetBytes( 91 ) );
        foreach( var c in f.Where( c => c != '-' ) )
        {
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".IndexOf( c ) >= 0).ShouldBeTrue( $"'{c}' is not a Base32 character." );
        }
    }

    [Test]
    public void Fingerprint_is_stable_and_distinguishes_keys()
    {
        var a = RandomNumberGenerator.GetBytes( 64 );
        var b = RandomNumberGenerator.GetBytes( 64 );
        PublicKeyFingerprint.Compute( a ).ShouldBe( PublicKeyFingerprint.Compute( a ) );
        PublicKeyFingerprint.Compute( a ).ShouldNotBe( PublicKeyFingerprint.Compute( b ) );
    }

    [Test]
    public void Fingerprint_is_the_Base32_of_the_first_20_bytes_of_the_SHA256()
    {
        // Guards against a silent change of the algorithm: a fingerprint that moves is worse than
        // no fingerprint, since operators compare it against what they were told out of band.
        var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var expectedHash = SHA256.HashData( data ).AsSpan( 0, 20 ).ToArray();
        var f = PublicKeyFingerprint.Compute( data );

        // Decode the Base32 back and compare with the truncated hash.
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int bitBuffer = 0, bitCount = 0, iByte = 0;
        var decoded = new byte[20];
        foreach( var c in f.Where( c => c != '-' ) )
        {
            bitBuffer = (bitBuffer << 5) | alphabet.IndexOf( c );
            bitCount += 5;
            if( bitCount >= 8 )
            {
                bitCount -= 8;
                decoded[iByte++] = (byte)((bitBuffer >> bitCount) & 0xFF);
            }
        }
        iByte.ShouldBe( 20 );
        decoded.ShouldBe( expectedHash );
    }
}
