using Microsoft.AspNetCore.DataProtection;
using System;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// A <see cref="IDataProtector"/> that behaves like a real one rather than like
/// <see cref="FakeProtector"/>: the protected payload carries a magic header and the content is
/// transformed, so <see cref="Unprotect(byte[])"/> throws a <see cref="CryptographicException"/>
/// when it is handed anything that this protector did not produce.
/// <para>
/// <see cref="FakeProtector"/> is the identity function. That makes it blind to a Protect/Unprotect
/// overload mismatch, because the two mismatched overloads cancel each other out. This one is not.
/// </para>
/// </summary>
public sealed class HeaderProtector : IDataProtector
{
    static readonly byte[] _magic = new byte[] { 0x09, 0xF9, 0x11, 0x02 };
    const byte Mask = 0x5A;

    public IDataProtector CreateProtector( string purpose ) => this;

    public byte[] Protect( byte[] clearData )
    {
        var r = new byte[_magic.Length + clearData.Length];
        _magic.CopyTo( r, 0 );
        for( int i = 0; i < clearData.Length; ++i )
        {
            r[_magic.Length + i] = (byte)(clearData[i] ^ Mask);
        }
        return r;
    }

    public byte[] Unprotect( byte[] protectedData )
    {
        if( protectedData.Length < _magic.Length
            || !protectedData.AsSpan( 0, _magic.Length ).SequenceEqual( _magic ) )
        {
            throw new CryptographicException( "The payload was not protected by this protector." );
        }
        var r = new byte[protectedData.Length - _magic.Length];
        for( int i = 0; i < r.Length; ++i )
        {
            r[i] = (byte)(protectedData[_magic.Length + i] ^ Mask);
        }
        return r;
    }
}
