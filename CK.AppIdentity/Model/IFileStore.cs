using CK.Core;

namespace CK.AppIdentity
{
    /// <summary>
    /// Offers basic file system functionalities to the parties shared or private folders.
    /// </summary>
    public interface IFileStore
    {
        /// <summary>
        /// Gets the <see cref="IParty"/>' folder that this trash bin handles.
        /// </summary>
        NormalizedPath FolderPath { get; }

        /// <summary>
        /// Gets the trash bin path.
        /// <para>
        /// Old trashed files are deleted when <see cref="ApplicationIdentityService"/> is disposed
        /// (or the application properly shuts down) or when the party is destroyed.
        /// </para>
        /// </summary>
        NormalizedPath TrashBinPath { get; }

        /// <summary>
        /// Tries to move a file that must be in <see cref="FolderPath"/> to the <see cref="TrashBinPath"/>.
        /// This returns true (no error) if the file doesn't exist.
        /// <para>
        /// The <paramref name="fullPath"/> must starts with <see cref="FolderPath"/> but not
        /// with <see cref="TrashBinPath"/> otherwise an <see cref="ArgumentException"/> is thrown.
        /// </para>
        /// </summary>
        /// <param name="logger">A <see cref="IActivityMonitor"/>, a <see cref="IParallelLogger"/> and even the <see cref="ActivityMonitor.StaticLogger"/> can be used.</param>
        /// <param name="fullPath">The full path of the file to trash.</param>
        /// <param name="immediateDelete">Optionally tries to delete the file immediately instead of moving it to the bin.</param>
        /// <returns>True on success, false on error.</returns>
        bool TryTrash( IActivityLineEmitter logger, in NormalizedPath fullPath, bool immediateDelete = false );
    }
}
