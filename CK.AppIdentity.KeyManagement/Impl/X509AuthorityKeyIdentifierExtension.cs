using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Security.Cryptography.X509Certificates
{
    // Waiting for NET7+
    sealed class X509AuthorityKeyIdentifierExtension : X509Extension
    {
        private static Oid AuthorityKeyIdentifierOid => new Oid( "2.5.29.35" );
        private static Oid SubjectKeyIdentifierOid => new Oid( "2.5.29.14" );

        public X509AuthorityKeyIdentifierExtension( X509Certificate2 certificateAuthority )
            : base( AuthorityKeyIdentifierOid, EncodeExtension( certificateAuthority ), true )
        {
        }

        static byte[] EncodeExtension( X509Certificate2 certificateAuthority )
        {
            var subjectKeyIdentifier = certificateAuthority.Extensions.Cast<X509Extension>().First( p => p.Oid?.Value == SubjectKeyIdentifierOid.Value );
            var rawData = subjectKeyIdentifier.RawData;
            var segment = new ArraySegment<byte>( rawData, 2, rawData.Length - 2 );
            var authorityKeyIdentifier = new byte[segment.Count + 4];
            // KeyID of the AuthorityKeyIdentifier
            authorityKeyIdentifier[0] = 0x30;
            authorityKeyIdentifier[1] = 0x16;
            authorityKeyIdentifier[2] = 0x80;
            authorityKeyIdentifier[3] = 0x14;
            segment.CopyTo( authorityKeyIdentifier, 4 );
            return authorityKeyIdentifier;
        }
    }
}

