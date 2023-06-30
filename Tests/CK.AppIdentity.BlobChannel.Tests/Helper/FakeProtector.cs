using Microsoft.AspNetCore.DataProtection;

namespace CK.AppIdentity.BlobChannel.Tests
{
    public sealed class FakeProtector : IDataProtector
    {
        public static readonly IDataProtector Fake = new FakeProtector();
        public IDataProtector CreateProtector( string purpose ) => Fake;
        public byte[] Protect( byte[] clearData ) => clearData;
        public byte[] Unprotect( byte[] protectedData ) => protectedData;
    }
}
