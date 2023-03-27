namespace CK.AppIdentity
{
    /// <summary>
    /// The optional <see cref="IRemoteParty.DomainApplicationIdentity"/>.
    /// This DomainName and EnvironmentName are the <see cref="Host"/>'s <see cref="IRemoteParty.DomainName"/>
    /// and <see cref="IRemoteParty.EnvironmentName"/>.
    /// </summary>
    public interface IDomainApplicationIdentity : IApplicationIdentity
    {
        /// <summary>
        /// Gets the remote party that hosts this domain.
        /// </summary>
        IRemoteParty Host { get; }
    }
}
