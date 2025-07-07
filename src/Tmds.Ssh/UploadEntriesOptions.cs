// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class UploadEntriesOptions
{
    public bool Overwrite { get; set; } = false;
    public bool IncludeSubdirectories { get; set; } = true;
    public bool FollowFileLinks { get; set; } = true;
    public bool FollowDirectoryLinks { get; set; } = true;
    public LocalFileEntryPredicate? ShouldRecurse { get; set; }
    public TargetDirectoryCreation TargetDirectoryCreation { get; set; } = TargetDirectoryCreation.None;
}