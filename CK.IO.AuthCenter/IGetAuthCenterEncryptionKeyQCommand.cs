using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// Gets the current encryption key of the Authentication Center: a party whose Authentication Center is remote encrypts
/// with it the sensitive fields of the commands it sends to it. Internal to the System and executed by the receiving
/// endpoint only (the handler checks the calling remote).
/// </summary>
[Internal]
public interface IGetAuthCenterEncryptionKeyQCommand : ICommand<IAuthCenterEncryptionKey>, ICommandEndpointOnly
{
}
