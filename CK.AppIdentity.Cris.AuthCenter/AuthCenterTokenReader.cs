using CK.Auth;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Implements <see cref="IAuthenticationTokenReader"/> with the <see cref="CrisAuthCenter"/> of the <see cref="CurrentLocalParty"/>
/// (see <see cref="CrisAuthCenter.ReadTokenAsync"/>). Without an Authentication Center, every token is refused.
/// </summary>
public sealed class AuthCenterTokenReader : IAuthenticationTokenReader
{
    readonly CurrentLocalParty _localParty;

    /// <summary>
    /// Initializes a new token reader.
    /// </summary>
    /// <param name="localParty">The current local party.</param>
    public AuthCenterTokenReader( CurrentLocalParty localParty )
    {
        _localParty = localParty;
    }

    /// <inheritdoc />
    public async ValueTask<AuthenticationTokenData?> ReadTokenAsync( IActivityMonitor monitor, string token )
    {
        Throw.CheckNotNullArgument( token );
        var center = _localParty.LocalParty.GetFeature<CrisAuthCenter>();
        if( center == null )
        {
            monitor.Warn( $"Token refused: '{_localParty.LocalParty}' has no AuthCenter." );
            return null;
        }
        var read = await center.ReadTokenAsync( monitor, token, DateTime.UtcNow ).ConfigureAwait( false );
        return read == null ? null : new AuthenticationTokenData( read.Info, read.BindingSecretHash );
    }
}
