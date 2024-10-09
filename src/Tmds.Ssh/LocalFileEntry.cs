// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.IO.Enumeration;

namespace Tmds.Ssh;

public delegate bool LocalFileEntryPredicate(ref LocalFileEntry entry);

// Library version of FileSystemEntry.
public ref struct LocalFileEntry
{
    private readonly FileSystemEntry _entry;

    public string ToFullPath() => _entry.ToFullPath();

    internal LocalFileEntry(ref FileSystemEntry entry)
    {
        _entry = entry;
    }
}