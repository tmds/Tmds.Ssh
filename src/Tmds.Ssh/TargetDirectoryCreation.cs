// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Behavior for target directory creation.
/// </summary>
public enum TargetDirectoryCreation
{
    /// <summary>
    /// Do not create the target directory.
    /// </summary>
    None,

    /// <summary>
    /// Create the target directory. Does not fail if it already exists.
    /// </summary>
    Create,

    /// <summary>
    /// Create the target directory and parent directories.
    /// </summary>
    CreateWithParents,

    /// <summary>
    /// Create the target directory. Fails if it already exists.
    /// </summary>
    CreateNew,
}