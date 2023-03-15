namespace CK.AppIdentity.PocoChannel
{
    /// <summary>
    /// Opaque handle to stored Poco.
    /// </summary>
    public readonly struct StoredPocoHandle
    {
        readonly long _id;

        internal StoredPocoHandle( long id )
        {
            _id = id;
        }

        /// <summary>
        /// Gets whether this is a valid handle.
        /// </summary>
        public bool IsValid => _id != 0;
    }
}
