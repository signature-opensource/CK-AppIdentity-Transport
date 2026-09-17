using CK.Core;
using System.IO;
using System.Linq;

namespace CK.AppIdentity.TransportLayer.Tests.Adversarial;

/// <summary>
/// Store surgery for adversarial tests.
/// <para>
/// A remote's trusted identity is persisted as <c>Identity.&lt;TimeName&gt;.public</c> under
/// <c>&lt;StoreRoot&gt;/#Dev/&lt;remote full name&gt;/</c> — that is, it is keyed by the
/// <b>remote's name alone</b> and is shared by every local party in the same store. Two tests that
/// each declare a remote called <c>$AdvPeer</c> therefore share one trusted key, and a test rerun
/// inherits the trust established by the previous run.
/// </para>
/// <para>
/// Adversarial tests turn on exactly this state ("do we already trust a key for this remote?"), so
/// they must control it rather than inherit it. Give each test its own remote name and call
/// <see cref="ClearRemoteTrust"/> before starting.
/// </para>
/// </summary>
static class PeerStore
{
    /// <summary>
    /// Deletes any persisted trusted identity for a remote, so the test starts from
    /// "we trust nothing for this party".
    /// </summary>
    /// <param name="remoteFullName">The remote's name without the domain, e.g. "Test/$AdvPeer".</param>
    public static void ClearRemoteTrust( string remoteFullName )
    {
        var folder = GetRemoteFolder( remoteFullName );
        if( Directory.Exists( folder ) ) Directory.Delete( folder, recursive: true );
    }

    /// <summary>
    /// Deletes a local party's own folder (identity keys and nonce cache), so the test starts from
    /// a party that has never run.
    /// </summary>
    /// <param name="localFullName">The local party's name without the domain, e.g. "Test/$Sender".</param>
    public static void ClearLocalParty( string localFullName )
    {
        var folder = GetRemoteFolder( localFullName );
        if( Directory.Exists( folder ) ) Directory.Delete( folder, recursive: true );
    }

    /// <summary>
    /// Gets the persisted trusted identity file for a remote, or null when there is none.
    /// </summary>
    public static string? FindTrustedIdentityFile( string remoteFullName )
    {
        var folder = GetRemoteFolder( remoteFullName );
        return Directory.Exists( folder )
                ? Directory.EnumerateFiles( folder, "Identity.*.public" ).FirstOrDefault()
                : null;
    }

    static NormalizedPath GetRemoteFolder( string fullNameWithoutDomain )
        => ApplicationIdentityServiceConfiguration.DefaultStoreRootPath
                .Combine( "#Dev" )
                .Combine( fullNameWithoutDomain );
}
