using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Describes a Remote party waiting for validation: this is
    /// a view of the initial message that has been sent to one of this
    /// incoming end points.
    /// </summary>
    public interface IUnknownRemote
    {
        /// <summary>
        /// Gets the remote party full name.
        /// </summary>
        string IncomingFullName { get; }

        /// <summary>
        /// Gets the description of the endpoint that received this new remote.
        /// </summary>
        string IncomingEndPointDescription { get; }

        /// <summary>
        /// Gets the message protocols supported by this remote.
        /// </summary>
        IReadOnlyCollection<string> AvailableProtocols { get; }

        /// <summary>
        /// Gets the public keys.
        /// </summary>
        IReadOnlyList<PublicKey> PublicKeys { get; }
    }
}
