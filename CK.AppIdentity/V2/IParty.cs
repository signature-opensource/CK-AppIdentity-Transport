namespace CK.AppIdentity
{
    /// <summary>
    /// Generalizes <see cref="LocalParty"/>, <see cref="RemoteParty"/>.
    /// </summary>
    public interface IParty : IApplicationIdentityObject
    {
        /// <summary>
        /// Gets this party's domain.
        /// This can be the root <see cref="ApplicationIdentityService"/> or a <see cref="RemoteDomain"/>.
        /// </summary>
        ApplicationIdentityDomain Domain { get; }

        /// <summary>
        /// Gets this party name.
        /// </summary>
        string PartyName { get; }

        /// <summary>
        /// Gets whether this party is hosted by the root <see cref="ApplicationIdentityService"/>
        /// or by a subordinated <see cref="RemoteDomain"/>.
        /// </summary>
        bool IsRooted { get; }

        /// <summary>
        /// Gets whether this party has been removed from the root <see cref="ApplicationIdentityService"/>.
        /// </summary>
        bool IsDestroyed { get; }
    }
}
