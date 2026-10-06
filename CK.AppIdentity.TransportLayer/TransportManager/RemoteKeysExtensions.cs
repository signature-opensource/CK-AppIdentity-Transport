using CK.AppIdentity.KeyManagement;
using CK.Core;

namespace CK.AppIdentity.TransportLayer;

static class RemoteKeysExtensions
{
    /// <summary>
    /// Tells whether a message whose identity block has been read may be acted upon, that is whether
    /// the sender is authenticated as this remote.
    /// <para>
    /// This is the single place where "the signature verifies" becomes "this really is our remote".
    /// A <see cref="SignatureCheck.SelfAsserted"/> message is accepted only if
    /// <see cref="IRemoteKeys.AutoTrustKey"/> pins the presented head — a trust-on-first-use decision,
    /// not a proof.
    /// </para>
    /// <para>
    /// The pin statement the message carries is reported to our own keys only when the sender is
    /// <see cref="SignatureCheck.Trusted"/>: a statement from anyone else would let a stranger raise
    /// alerts about us.
    /// </para>
    /// </summary>
    /// <param name="this">This remote keys.</param>
    /// <param name="logger">The logger to use.</param>
    /// <param name="check">The signature check result.</param>
    /// <param name="block">What was read (null when the message was unsigned).</param>
    /// <returns>True if the message can be trusted, false if it must be discarded.</returns>
    public static bool IsTrustedAfterRead( this IRemoteKeys @this,
                                           IParallelLogger logger,
                                           SignatureCheck check,
                                           in IdentityBlock? block )
    {
        if( check == SignatureCheck.Failed || block == null ) return false;
        var b = block.Value;
        if( check == SignatureCheck.Trusted )
        {
            if( b.StatedSeq is int seq )
            {
                @this.LocalKeys.ReportPinStatement( logger, @this.Party.FullName, seq, b.StatedDigest );
            }
            return true;
        }
        return @this.AdoptSelfAsserted( logger, b.Head );
    }
}
