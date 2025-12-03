// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.IO.Enumeration;

namespace Tmds.Ssh;

/// <summary>
/// Delegate for filtering local file entries.
/// </summary>
/// <param name="entry">The file entry to evaluate.</param>
/// <returns><see langword="true"/> to include the entry; otherwise, <see langword="false"/>.</returns>
public delegate bool LocalFileEntryPredicate(ref LocalFileEntry entry);

/// <summary>
/// Represents a local file entry during enumeration.
/// </summary>
public ref struct LocalFileEntry
{
    private readonly FileSystemEntry _entry;

    /// <summary>
    /// Gets the full path of the entry as a string.
    /// </summary>
    /// <returns>The full path.</returns>
    public string ToFullPath() => _entry.ToFullPath();

    internal LocalFileEntry(ref FileSystemEntry entry)
    {
        _entry = entry;
    }
}