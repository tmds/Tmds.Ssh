// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class UploadEntriesOptions
{
    public bool Overwrite { get; set; } = false;
    public bool RecurseSubdirectories { get; set; } = true;
}