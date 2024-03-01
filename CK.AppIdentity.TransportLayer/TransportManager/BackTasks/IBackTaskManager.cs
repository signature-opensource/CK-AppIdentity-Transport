namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// BackTaskManager seen by <see cref="BackTask"/>.
    /// </summary>
    public interface IBackTaskManager<out THost>
    {
        /// <summary>
        /// Gets the host.
        /// </summary>
        THost Host { get; }

        /// <summary>
        /// Gets the total number of ticks from the start of the host.
        /// </summary>
        int TotalTicks { get; }
    }
}
