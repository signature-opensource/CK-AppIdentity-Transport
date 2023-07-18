using CK.AppIdentity.KeyManagement;

namespace CK.AppIdentity.TransportLayer
{
    public interface IIncomingRequest
    {
        /// <summary>
        /// Gets the "0 Protocol" version.
        /// </summary>
        int Version { get; }

        /// <summary>
        /// Gets the <see cref="TransportListener.EndPointDescription"/> that received this message.
        /// </summary>
        string IncomingEndPointDescription { get; }

        /// <summary>
        /// Gets the <see cref="Transport.RemoteEndPointDescription"/> of the transport.
        /// </summary>
        string RemoteEndPointDescription { get; }

        /// <summary>
        /// Gets the domain name: it is the <see cref="ILocalParty"/>'s <see cref="IParty.DomainName"/>
        /// of the remote that sends the message.
        /// <para>
        /// It can be the root local domain, or a <see cref="TenantDomainParty"/> domain.
        /// </para>
        /// </summary>
        string DomainName { get; }

        /// <summary>
        /// Gets the party name: it is the <see cref="ILocalParty"/>'s <see cref="IParty.PartyName"/>
        /// of the remote that sends the message.
        /// <para>
        /// It can be the root local name, or a <see cref="TenantDomainParty"/> name.
        /// </para>
        /// </summary>
        string PartyName { get; }

        /// <summary>
        /// Gets the environment name of the remote that sends the message.
        /// </summary>
        string EnvironmentName { get; }

        /// <summary>
        /// Gets the party full name: it is the <see cref="ILocalParty"/> full name of
        /// the remote that sends the message.
        /// <para>
        /// It can be the root local full name, or a <see cref="TenantDomainParty"/> full name.
        /// </para>
        /// </summary>
        string FullName { get; }

        /// <summary>
        /// Gets the instance identifier of the calling process.
        /// </summary>
        string InstanceId { get; }

        /// <summary>
        /// Gets the list of protocols with their versions that must be supported.
        /// </summary>
        IReadOnlyCollection<string> AvailableProtocols { get; }

        /// <summary>
        /// Gets the current remote identity.
        /// </summary>
        RemoteIdentityKeyData CurrentRemoteIdentity { get; }

        /// <summary>
        /// Gets the clock offset between us and the remote.
        /// </summary>
        TimeSpan ClockOffset { get; }

        /// <summary>
        /// Gets whether the <see cref="ClockOffset"/> is small enough or too
        /// large to work with the party.
        /// </summary>
        bool ValidClockOffset { get; }
    }
}
