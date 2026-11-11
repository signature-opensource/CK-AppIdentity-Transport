using CK.AppIdentity.KeyManagement;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// <see cref="PartyEncryption.TryDecrypt"/> on hostile input (KM-5): it refuses, never throws, and a ciphertext can't be
/// re-encoded with another ephemeral point that gives the same shared secret.
/// </summary>
[TestFixture]
public class PartyEncryptionTests
{
    // keyId(8) || len16 || ephemeral SPKI || ticks(8) || nonce(12) || tag(16) || cipher.
    static byte[] ReplaceEphemeral( byte[] encrypted, byte[] spki )
    {
        int length = BinaryPrimitives.ReadUInt16BigEndian( encrypted.AsSpan( PartyEncryption.KeyIdLength ) );
        var start = PartyEncryption.KeyIdLength + 2;
        var r = new byte[encrypted.Length - length + spki.Length];
        encrypted.AsSpan( 0, PartyEncryption.KeyIdLength ).CopyTo( r );
        BinaryPrimitives.WriteUInt16BigEndian( r.AsSpan( PartyEncryption.KeyIdLength ), (ushort)spki.Length );
        spki.CopyTo( r.AsSpan( start ) );
        encrypted.AsSpan( start + length ).CopyTo( r.AsSpan( start + spki.Length ) );
        return r;
    }

    static byte[] EphemeralOf( byte[] encrypted )
    {
        int length = BinaryPrimitives.ReadUInt16BigEndian( encrypted.AsSpan( PartyEncryption.KeyIdLength ) );
        return encrypted.AsSpan( PartyEncryption.KeyIdLength + 2, length ).ToArray();
    }

    [Test]
    public void hostile_ephemeral_keys_are_refused_without_throwing()
    {
        using var recipient = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP256 );
        var spki = recipient.ExportSubjectPublicKeyInfo();
        var now = DateTime.UtcNow;
        var encrypted = PartyEncryption.Encrypt( spki, "secret"u8, "context"u8, now, out _ );
        ECDiffieHellman? Find( byte[] id ) => recipient;

        PartyEncryption.TryDecrypt( TestHelper.Monitor, encrypted, Find, "context"u8, now, TimeSpan.FromMinutes( 1 ), out var plain, out _ ).ShouldBeTrue();
        plain.ShouldBe( "secret"u8.ToArray() );

        // An ephemeral key of another curve imports fine: the key agreement used to throw.
        using var p384 = ECDiffieHellman.Create( ECCurve.NamedCurves.nistP384 );
        var other = ReplaceEphemeral( encrypted, p384.ExportSubjectPublicKeyInfo() );
        PartyEncryption.TryDecrypt( TestHelper.Monitor, other, Find, "context"u8, now, TimeSpan.FromMinutes( 1 ), out plain, out var responseKey ).ShouldBeFalse();
        plain.ShouldBeNull();
        responseKey.ShouldBeNull();

        // -E gives the same raw secret (its x-coordinate): the ciphertext re-encoded with it must not decrypt.
        using var e = ECDiffieHellman.Create();
        e.ImportSubjectPublicKeyInfo( EphemeralOf( encrypted ), out _ );
        var p = e.ExportParameters( false );
        var prime = BigInteger.Parse( "0FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", System.Globalization.NumberStyles.HexNumber );
        var y = new BigInteger( p.Q.Y, isUnsigned: true, isBigEndian: true );
        var negY = (prime - y).ToByteArray( isUnsigned: true, isBigEndian: true );
        var paddedY = new byte[32];
        negY.CopyTo( paddedY, 32 - negY.Length );
        p.Q.Y = paddedY;
        using var negated = ECDiffieHellman.Create( p );
        var reencoded = ReplaceEphemeral( encrypted, negated.ExportSubjectPublicKeyInfo() );
        PartyEncryption.TryDecrypt( TestHelper.Monitor, reencoded, Find, "context"u8, now, TimeSpan.FromMinutes( 1 ), out plain, out _ ).ShouldBeFalse();
    }
}
