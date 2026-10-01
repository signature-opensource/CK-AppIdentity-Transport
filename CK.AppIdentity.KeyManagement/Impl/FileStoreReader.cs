using CK.Core;
using System.IO;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Reads files through an <see cref="IFileStore"/>.
/// <para>
/// Reading through the store (rather than <see cref="File.ReadAllBytes(string)"/>) opens the file
/// with <see cref="FileShare.Delete"/>: on Windows, a reader then never prevents
/// <see cref="IFileStore.WriteAtomically"/> from replacing the file.
/// </para>
/// </summary>
static class FileStoreReader
{
    /// <summary>
    /// Reads the content of an existing file of the store.
    /// </summary>
    /// <param name="store">This store.</param>
    /// <param name="fullPath">The full path of the file to read.</param>
    /// <returns>The file content.</returns>
    public static byte[] ReadAllBytes( this IFileStore store, in NormalizedPath fullPath )
    {
        using var s = store.OpenReadStream( fullPath, options: FileOptions.SequentialScan );
        var bytes = new byte[s.Length];
        s.ReadExactly( bytes );
        return bytes;
    }
}
