// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>Base class for monitoring SFTP operations. Override the methods you are interested in.</summary>
/// <remarks>
/// <para>Callbacks are invoked inline and entry callbacks may be called concurrently. Progress reporting should be deferred to the UI thread.</para>
/// <para><see cref="Start"/> and <see cref="Completed"/> are always called. Other callbacks are not guaranteed:
/// if the operation fails before entry processing begins, <see cref="Start"/> may be followed directly by <see cref="Completed"/> without any <see cref="EntryStart"/> calls.
/// If a failure occurs after <see cref="EntryStart"/>, <see cref="EntryCompleted"/> may not be called for that entry.</para>
/// </remarks>
public abstract class SftpProgressHandler
{
    /// <summary>Called when the operation starts.</summary>
    protected internal virtual void Start() { }

    /// <summary>Called when the operation finishes.</summary>
    /// <param name="exception"><see langword="null"/> on success, the exception that the method throws on failure.</param>
    protected internal virtual void Completed(Exception? exception) { }

    /// <summary>Called when handling of an entry starts.</summary>
    /// <param name="path">The source path of the entry, or empty for stream uploads.</param>
    /// <param name="entry">Information about the entry.</param>
    protected internal virtual void EntryStart(string path, Entry entry) { }

    /// <summary>Called when data is transferred.</summary>
    /// <param name="path">The source path of the entry.</param>
    /// <param name="bytesTransferred">The additional number of bytes transferred.</param>
    /// <param name="offset">The position in the remote file after the transfer.</param>
    protected internal virtual void DataTransferred(string path, long bytesTransferred, long offset) { }

    /// <summary>Called when an entry was skipped because it was not found at the time of transfer.</summary>
    /// <remarks><see cref="EntryCompleted"/> is still called after this method.</remarks>
    /// <param name="path">The source path of the entry.</param>
    protected internal virtual void EntrySkipped(string path) { }

    /// <summary>Called when an entry has been successfully handled.</summary>
    /// <param name="path">The source path of the entry.</param>
    protected internal virtual void EntryCompleted(string path) { }

    /// <summary>Called when all entries have been discovered. No more <see cref="EntryStart"/> calls will follow.</summary>
    protected internal virtual void EntriesDiscovered() { }

    /// <summary>Describes an entry being handled.</summary>
    public readonly struct Entry
    {
        /// <summary>The type of entry (regular file, directory, symlink, etc.).</summary>
        public UnixFileType FileType { get; init; }

        /// <summary>The expected length of the source data, or <see langword="null"/> if unknown.</summary>
        public long? SourceLength { get; init; }
    }
}
