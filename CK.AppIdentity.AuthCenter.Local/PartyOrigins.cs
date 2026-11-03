using System;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The origins of the parties of a local AuthCenter: the origin of the <see cref="PartyDescription.PublicUrl"/> of the
/// local party and of each of its remotes (their announcement). The URLs that a remote relays to the AuthCenter (the
/// callback of a remote login, the origin of a passkey ceremony) must be on one of them: they are derived from what the
/// parties state about themselves, never configured on the AuthCenter.
/// </summary>
public static class PartyOrigins
{
    /// <summary>
    /// Gets whether the origin (scheme, host and port) of an absolute URL is the one of the public URL of the local party
    /// or of one of its remotes.
    /// </summary>
    /// <param name="local">The local party (the AuthCenter).</param>
    /// <param name="url">The URL to check.</param>
    /// <returns>True if the URL is on the origin of one of the parties.</returns>
    public static bool IsPartyUrl( ILocalParty local, string? url )
    {
        if( !Uri.TryCreate( url, UriKind.Absolute, out var u ) ) return false;
        var origin = u.GetLeftPart( UriPartial.Authority );
        if( IsOrigin( local.Description, origin ) ) return true;
        foreach( var r in local.Remotes )
        {
            if( IsOrigin( r.Description, origin ) ) return true;
        }
        return false;

        static bool IsOrigin( PartyDescription d, string origin )
            => d.PublicUrl != null && string.Equals( d.PublicUrl.GetLeftPart( UriPartial.Authority ), origin, StringComparison.OrdinalIgnoreCase );
    }
}
