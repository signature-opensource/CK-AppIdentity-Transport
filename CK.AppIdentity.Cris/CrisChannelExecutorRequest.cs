using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Specialized to carry an optional authentication token that captures a <see cref="Auth.IAuthenticationInfo"/>
    /// thanks to the <see cref="IAuthenticationInfoTokenService"/> service.
    /// </summary>
    public sealed class CrisChannelExecutorRequest : CrisExecutorRequest
    {
        public CrisChannelExecutorRequest( ICrisPoco payload, ActivityMonitor.DependentToken issuerToken, string? authToken )
            : base( payload, issuerToken )
        {
            AuthToken = authToken;
        }

        public string? AuthToken { get; }
    }
}
