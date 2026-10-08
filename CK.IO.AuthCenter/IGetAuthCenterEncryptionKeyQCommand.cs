using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// Gets the current encryption key of the Authentication Center: a front encrypts the sensitive fields of the session
/// commands it relays with it.
/// </summary>
public interface IGetAuthCenterEncryptionKeyQCommand : ICommand<IAuthCenterEncryptionKey>
{
}
