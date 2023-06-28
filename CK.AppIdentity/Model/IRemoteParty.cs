namespace CK.AppIdentity
{
    /// <summary>
    /// A remote party can be an external one.
    /// </summary>
    public interface IRemoteParty : IOwnedParty
    {
        /// <summary>
        /// Gets the <see cref="RemotePartyConfiguration"/> object.
        /// </summary>
        new RemotePartyConfiguration Configuration { get; }

        /// <summary>
        /// Gets whether this is an External party.
        /// </summary>
        bool IsExternalParty { get; }

        /// <summary>
        /// Gets the address of this party.
        /// This is null if this application cannot reach the remote (this remote must be a server that accepts the remote as a client).
        /// <para>
        /// This can also be null for external parties when the party is well known and features don't need a specific address (a GitHubApp
        /// feature for instance knows the default GitHub address).
        /// </para>
        /// </summary>
        string? Address { get; }

    }
}
