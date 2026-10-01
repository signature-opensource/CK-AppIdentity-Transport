using CK.Core;
using System;
using System.IO;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Writes the files that hold, or anchor, key material.
/// <para>
/// <see cref="File.WriteAllBytes(string,byte[])"/> creates with the process umask, which is 022 on a
/// typical Linux host: the encrypted PFX, the DataProtection-protected password beside it and the
/// <c>.public</c> trust anchors all landed 0644, readable by every local account. The mode is applied
/// at creation rather than afterwards, so the file never exists with wider permissions - a chmod
/// after the write leaves exactly that window open.
/// </para>
/// <para>
/// On Windows <see cref="FileStreamOptions.UnixCreateMode"/> is not supported at all (setting it
/// throws), so the file inherits the directory ACL there, which is the platform's own answer to the
/// same question.
/// </para>
/// <para>
/// This covers the files this repository writes. The directories holding them are created by the
/// file-store abstraction in <c>CK-AppIdentity</c>, outside this repository: write access to the
/// shared store still repoints a pinned identity, and that half has to be closed there.
/// </para>
/// </summary>
static class SecretFile
{
    const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>
    /// Creates or replaces a file readable and writable by its owner only.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="content">The bytes to write.</param>
    public static void WriteAllBytes( NormalizedPath path, ReadOnlySpan<byte> content )
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.SequentialScan
        };
        if( !OperatingSystem.IsWindows() ) options.UnixCreateMode = OwnerOnly;
        using var f = new FileStream( path, options );
        f.Write( content );
    }
}
