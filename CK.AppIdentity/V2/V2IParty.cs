namespace CK.AppIdentity
{
    /// <summary>
    /// Generalizes <see cref="V2LocalParty"/>, <see cref="V2RemoteParty"/>.
    /// </summary>
    public interface V2IParty : V2IAppIdentityObject
    {
        /// <summary>
        /// Gets this party's domain.
        /// This can be the root <see cref="V2ApplicationIdentityService"/> or a <see cref="V2RemoteDomain"/>.
        /// </summary>
        V2AppIdentityDomain Domain { get; }

        /// <summary>
        /// Gets this party name.
        /// </summary>
        string PartyName { get; }

        /// <summary>
        /// Gets whether this party is hosted by the root <see cref="V2ApplicationIdentityService"/>
        /// or by a subordinated <see cref="V2RemoteDomain"/>.
        /// </summary>
        bool IsRooted { get; }

        /// <summary>
        /// Gets whether this party has been removed from the root <see cref="V2ApplicationIdentityService"/>.
        /// </summary>
        bool IsDestroyed { get; }
    }
}
