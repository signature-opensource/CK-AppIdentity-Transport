using System;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The origins of the parties of a local AuthCenter: the origin of the <see cref="PartyDescription.PublicUrl"/> of the
/// local party and of each of its remotes (their announcement). The URLs that a party relays to the AuthCenter (the
/// callback of a remote login, the origin of a passkey ceremony) must be on the origin of <b>this</b> party, the caller
/// party of the operation: they are derived from what the parties state about themselves, never configured on the
/// AuthCenter, and a party can't start or complete a login for another one.
/// </summary>
public static class PartyOrigins
{
    /// <summary>
    /// Gets whether the origin (scheme, host and port) of an absolute URL is the one of the public URL of the caller
    /// party (see <see cref="CallerPartyExtensions.FindCallerParty"/>): the local party itself, or the remote that relays
    /// the operation.
    /// </summary>
    /// <param name="local">The local party (the AuthCenter).</param>
    /// <param name="callerPartyId">The caller party identifier (<see cref="CK.Auth.AuthenticationInfo.CallerPartyId"/>).</param>
    /// <param name="url">The URL to check.</param>
    /// <returns>True if the URL is on the origin of the caller party.</returns>
    public static bool IsCallerPartyUrl( ILocalParty local, int callerPartyId, string? url )
    {
        if( !Uri.TryCreate( url, UriKind.Absolute, out var u ) ) return false;
        var publicUrl = local.FindCallerParty( callerPartyId )?.Description.PublicUrl;
        return publicUrl != null
               && string.Equals( publicUrl.GetLeftPart( UriPartial.Authority ), u.GetLeftPart( UriPartial.Authority ), StringComparison.OrdinalIgnoreCase );
    }
}
