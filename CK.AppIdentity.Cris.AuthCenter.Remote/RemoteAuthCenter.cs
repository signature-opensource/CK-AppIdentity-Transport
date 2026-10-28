using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.IO.AuthCenter;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The feature of a local party whose Authentication Center is a remote party: this application is a remote of it.
/// Added by the <see cref="RemoteAuthCenterFeatureDriver"/>.
/// </summary>
public sealed class RemoteAuthCenter
{
    /// <summary>
    /// The maximal time to wait for the remote Authentication Center: 30 seconds.
    /// </summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds( 30 );

    readonly CrisAuthCenter _center;
    // The encryption key of the Authentication Center, until the expiration of its signature.
    (byte[] Spki, DateTime Expires)? _encryptionKey;

    internal RemoteAuthCenter( CrisAuthCenter center )
    {
        Throw.DebugAssert( center.AuthCenter is IRemoteParty );
        _center = center;
    }

    /// <summary>
    /// Gets the shared <see cref="CrisAuthCenter"/> feature: its <see cref="CrisAuthCenter.AuthCenter"/> is the remote
    /// Authentication Center.
    /// </summary>
    public CrisAuthCenter Center => _center;

    /// <summary>
    /// Gets the current encryption key of the Authentication Center: it is asked for over the Cris channel, its signature
    /// is verified (with the same safety net as the tokens) and it is cached until it expires.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="channel">The Cris channel to the Authentication Center.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The SubjectPublicKeyInfo of the key, or null if it cannot be obtained (the reason is logged).</returns>
    internal async ValueTask<byte[]?> GetEncryptionKeyAsync( IActivityMonitor monitor, CrisChannelFeature channel, PocoDirectory pocos )
    {
        var cached = _encryptionKey;
        if( cached.HasValue && cached.Value.Expires - TimeSpan.FromMinutes( 1 ) > DateTime.UtcNow ) return cached.Value.Spki;
        IAuthCenterEncryptionKey published;
        try
        {
            published = await channel.SendCommand( monitor, pocos.Create<IGetAuthCenterEncryptionKeyQCommand>() )
                                     .WithResult<IAuthCenterEncryptionKey>().Result.WaitAsync( Timeout ).ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Error( $"Unable to get the encryption key of the AuthCenter '{_center.AuthCenter}'.", ex );
            return null;
        }
        byte[] spki, encodedSignature;
        try
        {
            spki = System.Buffers.Text.Base64Url.DecodeFromChars( published.PublicKey );
            encodedSignature = System.Buffers.Text.Base64Url.DecodeFromChars( published.Signature );
        }
        catch( FormatException )
        {
            monitor.Warn( $"The encryption key of the AuthCenter '{_center.AuthCenter}' is malformed." );
            return null;
        }
        if( !ApplicationSignature.TryRead( encodedSignature, out var signature )
            || await _center.CheckWithKeyEventsAsync( monitor, AuthCenterFieldEncryption.EncryptionKeyPurpose, spki, signature ).ConfigureAwait( false ) != SignatureVerdict.Valid )
        {
            monitor.Warn( $"The encryption key of the AuthCenter '{_center.AuthCenter}' is refused." );
            return null;
        }
        _encryptionKey = (spki, signature.Expiration);
        return spki;
    }

    /// <summary>
    /// Overridden to return the Authentication Center and its owner.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => _center.ToString();
}
