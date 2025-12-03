// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Mode for opening a file.
/// </summary>
[Flags]
public enum OpenMode
{
    /// <summary>
    /// Default mode. Does not append or truncate.
    /// </summary>
    Default = 0,

    /// <summary>
    /// Append to the end of the file.
    /// </summary>
    Append = 1,

    /// <summary>
    /// Truncate the file to zero length.
    /// </summary>
    Truncate = 2
}
