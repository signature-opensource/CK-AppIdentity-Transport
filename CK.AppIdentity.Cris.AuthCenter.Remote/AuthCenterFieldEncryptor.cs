using CK.AppIdentity.Cris;
using CK.Core;
using CK.Cris;
using CK.Poco.Exc.Json;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Encrypts the [Sensitive] fields of a command sent to the Authentication Center of its local party (for instance the
/// password of a Basic login, in the payload of the operation that opens the session): only the Authentication Center can
/// read them. The fields are found by the generated <see cref="ICrisPocoModel.TransformSensitiveStrings"/>, in the command
/// and in its nested Cris Pocos. A copy is encrypted: the caller's command is left as is.
/// </summary>
public sealed class AuthCenterFieldEncryptor : ICrisOutgoingCommandTransformer
{
    readonly PocoDirectory _pocos;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterFieldEncryptor"/>.
    /// </summary>
    /// <param name="pocos">The poco directory.</param>
    public AuthCenterFieldEncryptor( PocoDirectory pocos )
    {
        _pocos = pocos;
    }

    /// <inheritdoc />
    public async ValueTask<IAbstractCommand?> TransformAsync( IActivityMonitor monitor, CrisChannelFeature channel, IAbstractCommand command )
    {
        // HasSensitiveData is conservative (a nested abstract command may have sensitive fields): when no sensitive field
        // has a value (the transformer only sees the non null values), there is nothing to encrypt.
        if( !command.CrisPocoModel.HasSensitiveData
            || command.CrisPocoModel.TransformSensitiveStrings( command, static ( o, p, v ) => null ) )
        {
            return command;
        }
        var remote = channel.Party.Owner.GetFeature<RemoteAuthCenter>();
        // Only for the Authentication Center (the generalization to any receiving party is not done).
        if( remote == null || remote.Center.AuthCenter != channel.Party ) return command;
        var spki = await remote.GetEncryptionKeyAsync( monitor, channel, _pocos ).ConfigureAwait( false );
        if( spki == null ) return null;
        var copy = Copy( monitor, command );
        if( copy == null ) return null;
        var utcNow = DateTime.UtcNow;
        var center = channel.Party.FullName;
        var sender = channel.Party.Owner.FullName;
        bool success = copy.CrisPocoModel.TransformSensitiveStrings( copy, ( owner, property, value ) =>
            AuthCenterFieldEncryption.Encrypt( spki, value, AuthCenterFieldEncryption.GetContext( center, sender, owner.CrisPocoModel.PocoName, property ), utcNow ) );
        return success ? copy : null;
    }

    // TODO: TEMPORARY WORKAROUND for the lack of a Poco clone (a JSON round-trip). To be replaced by the planned
    //       Create<T>() / Clone() of any Poco (see .wip/cris-auth/34-engine-ideas.md, "Create<T>() on any Poco").
    IAbstractCommand? Copy( IActivityMonitor monitor, IAbstractCommand command )
    {
        try
        {
            var json = command.ToString( PocoJsonExportOptions.ToStringDefault, withType: true );
            return _pocos.ReadJson( json, PocoJsonImportOptions.ToStringDefault ) as IAbstractCommand;
        }
        catch( Exception ex )
        {
            monitor.Error( $"Unable to copy '{command.CrisPocoModel.PocoName}' to encrypt its sensitive fields.", ex );
            return null;
        }
    }
}
