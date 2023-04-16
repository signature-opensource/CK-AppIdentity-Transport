namespace CK.Core
{
    /// <summary>
    /// Summarizes <see cref="BasicTrampolineRunner"/> execution result.
    /// </summary>
    public enum TrampolineResult
    {
        /// <summary>
        /// No exception at all have been thrown.
        /// </summary>
        TotalSuccess,

        /// <summary>
        /// An action thrown an exception or returned false.
        /// Error and finally handlers have been called. 
        /// </summary>
        Error = 1,

        /// <summary>
        /// At least one success handler thrown an exception.
        /// </summary>
        HasSuccessException = 2,

        /// <summary>
        /// At least one error handler thrown an exception.
        /// </summary>
        HasErrorException = 4,

        /// <summary>
        /// At least one finally handler thrown an exception.
        /// </summary>
        HasFinallyException = 8,
    }
}
