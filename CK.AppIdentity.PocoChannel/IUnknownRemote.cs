namespace CK.AppIdentity.PocoChannel
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
        string FullName { get; }

        /// <summary>
        /// Gets the description of the endpoint that received this new remote.
        /// </summary>
        string EndPointDescription { get; }
    }
}
