using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Handles the <see cref="IGetAuthCenterEncryptionKeyQCommand"/> of a remote: the current encryption key of the
/// Authentication Center, signed. Only a remote of the Authentication Center that has its "AuthCenter" feature (it shares
/// this Authentication Center) receives it.
/// </summary>
public sealed class AuthCenterEncryptionKeyHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the query.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="caller">The remote that sent it.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The signed public key.</returns>
    [CommandHandler]
    public IAuthCenterEncryptionKey Handle( IActivityMonitor monitor, IGetAuthCenterEncryptionKeyQCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var local = GetLocal( caller );
        if( local == null )
        {
            Throw.InvalidOperationException( $"'{caller}' is not a remote of an AuthCenter here." );
        }
        var (publicKey, signature) = local.EncryptionKeys.GetPublished( monitor, local.Party.GetRequiredFeature<ILocalKeys>(), DateTime.UtcNow );
        return pocos.Create<IAuthCenterEncryptionKey>( k =>
        {
            k.PublicKey = publicKey;
            k.Signature = signature;
        } );
    }

    /// <summary>
    /// Gets the local Authentication Center of a remote: the caller is a remote of a local party that is its own
    /// Authentication Center, and it allows "AuthCenterRemote" (it then shares its <see cref="CrisAuthCenter"/>).
    /// </summary>
    /// <param name="caller">The remote.</param>
    /// <returns>The local Authentication Center or null.</returns>
    public static LocalAuthCenter? GetLocal( IRemoteParty caller )
    {
        return caller.GetFeature<CrisAuthCenter>() is { } center && center.Owner == caller.Owner
                ? caller.Owner.GetFeature<LocalAuthCenter>()
                : null;
    }
}
