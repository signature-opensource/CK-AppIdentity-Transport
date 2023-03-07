namespace CK.AppIdentity
{
    /// <summary>
    /// A root remote party can define a domain: it exposes its own <see cref="DomainApplicationIdentity"/>.
    /// </summary>
    public interface IRootRemoteParty : IRemoteParty
    {
        /// <summary>
        /// Gets the <see cref="DomainApplicationIdentity"/> if this remote
        /// defines a domain.
        /// </summary>
        public DomainApplicationIdentity? DomainApplicationIdentity { get; }
    }
}
