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
    readonly TaskCompletionSource<bool> _partyActorIds;
    // The encryption key of the Authentication Center, until the expiration of its signature.
    (byte[] Spki, DateTime Expires)? _encryptionKey;

    internal RemoteAuthCenter( CrisAuthCenter center )
    {
        Throw.DebugAssert( center.AuthCenter is IRemoteParty );
        _center = center;
        _partyActorIds = new TaskCompletionSource<bool>( TaskCreationOptions.RunContinuationsAsynchronously );
    }

    /// <summary>
    /// Gets the shared <see cref="CrisAuthCenter"/> feature: its <see cref="CrisAuthCenter.AuthCenter"/> is the remote
    /// Authentication Center.
    /// </summary>
    public CrisAuthCenter Center => _center;

    /// <summary>
    /// Gets a task that completes when the <see cref="IParty.PartyActorId"/> of the local party and of the Authentication
    /// Center are resolved (true) or cannot be (false, the reason is logged). It never completes while the Authentication
    /// Center is not reachable: the identifiers stay 0 until the channel connects.
    /// </summary>
    public Task<bool> PartyActorIdsResolution => _partyActorIds.Task;

    // Called once all the features are set up. A party with an actors database has its identifiers already (the
    // CK.DB.AppIdentity registrar): nothing is asked then. Otherwise, they are asked on the Cris channel, sent as soon
    // as it connects.
    internal void StartPartyActorIdsResolution( IActivityMonitor monitor )
    {
        var center = (IRemoteParty)_center.AuthCenter;
        var local = center.Owner;
        if( local.PartyActorId != 0 && center.PartyActorId != 0 )
        {
            _partyActorIds.TrySetResult( true );
            return;
        }
        var channel = center.GetFeature<CrisChannelFeature>();
        if( channel == null )
        {
            monitor.Warn( $"No Cris channel to the AuthCenter '{center}': the PartyActor identifiers of '{local}' and '{center}' cannot be resolved." );
            _partyActorIds.TrySetResult( false );
            return;
        }
        var executing = channel.SendCommand( monitor, channel.PocoDirectory.Create<IGetPartyActorIdsQCommand>() ).WithResult<IPartyActorIds>();
        _ = OnPartyActorIdsAsync( executing.Result, local, center );
    }

    async Task OnPartyActorIdsAsync( Task<IPartyActorIds> result, ILocalParty local, IRemoteParty center )
    {
        var monitor = new ActivityMonitor( $"Resolving the PartyActor identifiers of '{local}' and '{center}'." );
        try
        {
            var ids = await result.ConfigureAwait( false );
            bool success = ids.CallerPartyActorId > 0 && ids.AuthCenterPartyActorId > 0;
            if( !success )
            {
                monitor.Warn( $"The AuthCenter '{center}' has not resolved the PartyActor identifiers of '{local}' and itself." );
            }
            else
            {
                success = local.TrySetPartyActorId( monitor, ids.CallerPartyActorId )
                          & center.TrySetPartyActorId( monitor, ids.AuthCenterPartyActorId );
            }
            _partyActorIds.TrySetResult( success );
        }
        catch( Exception ex )
        {
            monitor.Error( $"Unable to get the PartyActor identifiers from the AuthCenter '{center}'.", ex );
            _partyActorIds.TrySetResult( false );
        }
        finally
        {
            monitor.MonitorEnd();
        }
    }

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
