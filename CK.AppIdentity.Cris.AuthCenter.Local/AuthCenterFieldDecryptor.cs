using CK.AppIdentity.Cris;
using CK.Core;
using CK.Cris;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Decrypts the [Sensitive] fields of a command received from a remote of the Authentication Center (see the Remote side's
/// AuthCenterFieldEncryptor). A clear value is refused, and so is a sensitive value sent by a party that is not a remote of
/// an Authentication Center here (it cannot encrypt for it). <see cref="ICrisPocoModel.HasSensitiveData"/> is conservative
/// (a nested abstract command may have sensitive fields): only the actual values matter.
/// </summary>
public sealed class AuthCenterFieldDecryptor : ICrisIncomingCommandTransformer
{
    /// <inheritdoc />
    public bool Transform( IActivityMonitor monitor, IRemoteParty caller, IAbstractCommand command )
    {
        if( !command.CrisPocoModel.HasSensitiveData ) return true;
        var local = AuthCenterEncryptionKeyHandler.GetLocal( caller );
        if( local == null )
        {
            // No sensitive value at all (the transformer only sees the non null values) is fine.
            if( command.CrisPocoModel.TransformSensitiveStrings( command, static ( o, p, v ) => null ) ) return true;
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' sent '{command.CrisPocoModel.PocoName}' with sensitive values but is not a remote of an AuthCenter here. Refused." );
            return false;
        }
        var utcNow = DateTime.UtcNow;
        bool success = command.CrisPocoModel.TransformSensitiveStrings( command, ( owner, property, value ) =>
            AuthCenterFieldEncryption.TryDecrypt( monitor,
                                                  value,
                                                  id => local.EncryptionKeys.Find( id, utcNow ),
                                                  AuthCenterFieldEncryption.GetContext( local.Party.FullName, caller.FullName, owner.CrisPocoModel.PocoName, property ),
                                                  utcNow,
                                                  out var clear )
                ? clear
                : null );
        if( !success )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The sensitive fields of '{command.CrisPocoModel.PocoName}' sent by '{caller}' cannot be decrypted. Refused." );
        }
        return success;
    }
}
