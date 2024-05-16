// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

public sealed class FileOpenOptions
{
    public OpenMode OpenMode { get; set; } = OpenMode.Default;
    public UnixFilePermissions CreatePermissions { get; set; } = SftpClient.DefaultCreateFilePermissions;
}