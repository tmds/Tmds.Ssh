// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Options for uploading directory entries.
/// </summary>
public sealed class UploadEntriesOptions
{
    /// <summary>
    /// Gets or sets whether to overwrite existing files.
    /// </summary>
    public bool Overwrite { get; set; } = false;

    /// <summary>
    /// Gets or sets whether to include subdirectories.
    /// </summary>
    public bool IncludeSubdirectories { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to follow file symbolic links.
    /// </summary>
    public bool FollowFileLinks { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to follow directory symbolic links.
    /// </summary>
    public bool FollowDirectoryLinks { get; set; } = true;

    /// <summary>
    /// Gets or sets <see cref="LocalFileEntryPredicate"/> to determine if a directory should be recursed.
    /// </summary>
    public LocalFileEntryPredicate? ShouldRecurse { get; set; }

    /// <summary>
    /// Gets or sets <see cref="LocalFileEntryPredicate"/> to determine if an entry should be included.
    /// </summary>
    /// <remarks>
    /// Parent directories will be created for included entries when they don't exist yet with <see cref="SftpClient.DefaultCreateDirectoryPermissions"/>.
    /// </remarks>
    public LocalFileEntryPredicate? ShouldInclude { get; set; }

    /// <summary>
    /// Gets or sets how to handle target directory creation.
    /// </summary>
    public TargetDirectoryCreation TargetDirectoryCreation { get; set; } = TargetDirectoryCreation.CreateWithParents;
}