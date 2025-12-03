// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// SFTP error codes.
/// </summary>
public enum SftpError
{
    /// <summary>
    /// No error.
    /// </summary>
    None = 0,

    /// <summary>
    /// End of file reached.
    /// </summary>
    Eof = 1,

    /// <summary>
    /// File or directory not found.
    /// </summary>
    NoSuchFile = 2,

    /// <summary>
    /// Permission denied.
    /// </summary>
    PermissionDenied = 3,

    /// <summary>
    /// Operation failed.
    /// </summary>
    Failure = 4,

    /// <summary>
    /// Invalid value or path too long.
    /// </summary>
    BadMessage = 5,
    // NoConnection = 6,
    // ConnectionLost = 7,

    /// <summary>
    /// Operation not supported.
    /// </summary>
    Unsupported = 8
}
