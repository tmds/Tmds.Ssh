// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Numerics;

namespace Tmds.Ssh;

/// <summary>Base class for monitoring SFTP operations. Override the methods you are interested in.</summary>
/// <remarks>
/// <para>Callbacks are invoked inline. Progress reporting should be deferred to the UI thread.</para>
/// <para><see cref="Start"/> is always called synchronously before the async method returns its <see cref="System.Threading.Tasks.ValueTask"/>. <see cref="Completed"/> is called at the end, including when the operation fails.</para>
/// <para>Entries are identified by an <c>index</c> parameter. For single-entry operations the index is always 0.
/// For multi-entry operations, indexes are assigned and reused as entries finish.
/// The index value is always less than <c>64</c> for upload and download operations. For recursive delete operations, the index range may be larger but is bounded by the number of concurrent delete operations.</para>
/// <para>For each discovered entry, <see cref="EntryStart"/> is called.
/// <see cref="DataTransferred"/> is called for each chunk of data that is successfully transferred.
/// When the entry is successfully handled, <see cref="EntryCompleted"/> is called.
/// If a discovered entry is not found and this is not a failure, <see cref="EntrySkipped"/> is called instead of <see cref="EntryCompleted"/>.</para>
/// <para>After all entries have been discovered, <see cref="EntriesDiscovered"/> is called and no more <see cref="EntryStart"/> calls will follow.</para>
/// <para><see cref="EntryStart"/> calls are always sequential. <see cref="EntryCompleted"/>, <see cref="EntrySkipped"/>, and <see cref="DataTransferred"/> may be called concurrently for different entries but are sequential for the same entry.</para>
/// <para>Because <see cref="EntryStart"/> calls are sequential, they can be used to resize an array that tracks per-entry information using the index as position. Each new entry can fill in its information at start. Note that clearing information when an entry finishes may be lost if the array is resized by a concurrent <see cref="EntryStart"/> call.</para>
/// <para>For per-entry <see cref="DataTransferred"/> information, resizing does not work because it would affect tracking for on-going entries. A fixed-size array of <see cref="MaxConcurrentTransferEntries"/> elements can be used instead.</para>
/// </remarks>
public abstract class SftpProgressHandler
{
    /// <summary>The maximum number of concurrent entries for upload and download operations (64).</summary>
    public const int MaxConcurrentTransferEntries = 64;

    private long _allocatedIndexes;

    // Called from a single thread when an index will be free.
    internal int ReserveIndex64()
    {
        if (!TryReserveIndex(out int index))
        {
            throw new InvalidOperationException("All indexes are allocated.");
        }
        return index;
    }

    internal bool TryReserveIndex(out int index)
    {
        index = BitOperations.TrailingZeroCount(~(ulong)Volatile.Read(ref _allocatedIndexes));
        if (index >= 64)
        {
            return false;
        }
        // Use Interlocked to synchronize with concurrent ReturnIndex calls.
        Interlocked.Or(ref _allocatedIndexes, 1L << index);
        return true;
    }

    internal void ReturnIndex(int index)
    {
        if (index < 64)
        {
            Interlocked.And(ref _allocatedIndexes, ~(1L << index));
        }
    }

    /// <summary>Called when the operation starts.</summary>
    protected virtual void Start() { }

    internal void CallStart() => Start();

    /// <summary>Called when the operation finishes.</summary>
    /// <param name="exception"><see langword="null"/> on success, the exception that caused the operation to fail.</param>
    protected virtual void Completed(Exception? exception) { }

    internal void CallCompleted(Exception? exception)
    {
        Completed(exception);
        _allocatedIndexes = 0;
    }

    /// <summary>Called when handling of an entry starts.</summary>
    /// <param name="index">The index of the entry in discovery order.</param>
    /// <param name="type">The type of entry.</param>
    /// <param name="entry">Information about the entry.</param>
    protected virtual void EntryStart(int index, UnixFileType type, Entry entry) { }

    internal void CallEntryStart(int index, UnixFileType type, Entry entry) => EntryStart(index, type, entry);

    /// <summary>Called when data is transferred.</summary>
    /// <param name="index">The index of the entry.</param>
    /// <param name="bytesTransferred">The additional number of bytes transferred.</param>
    /// <param name="offset">The position in the remote file after the transfer.</param>
    protected virtual void DataTransferred(int index, long bytesTransferred, long offset) { }

    internal void CallDataTransferred(int index, long bytesTransferred, long offset) => DataTransferred(index, bytesTransferred, offset);

    /// <summary>Called when an entry was skipped because it was not found at the time of transfer.</summary>
    /// <remarks>The default implementation calls <see cref="EntryCompleted"/>.</remarks>
    /// <param name="index">The index of the entry.</param>
    /// <param name="type">The type of entry.</param>
    protected virtual void EntrySkipped(int index, UnixFileType type) => EntryCompleted(index, type);

    internal void CallEntrySkipped(int index, UnixFileType type)
    {
        EntrySkipped(index, type);
        ReturnIndex(index);
    }

    /// <summary>Called when an entry has been successfully handled.</summary>
    /// <param name="index">The index of the entry.</param>
    /// <param name="type">The type of entry.</param>
    protected virtual void EntryCompleted(int index, UnixFileType type) { }

    internal void CallEntryCompleted(int index, UnixFileType type)
    {
        EntryCompleted(index, type);
        ReturnIndex(index);
    }

    /// <summary>Called when all entries have been discovered. No more <see cref="EntryStart"/> calls will follow.</summary>
    protected virtual void EntriesDiscovered() { }

    internal void CallEntriesDiscovered() => EntriesDiscovered();

    /// <summary>Describes an entry being handled.</summary>
    public readonly struct Entry
    {
        /// <summary>The source path of the entry.</summary>
        public string SourcePath { get; init; }

        /// <summary>The expected length of the source data, or <see langword="null"/> if unknown.</summary>
        public long? SourceLength { get; init; }
    }
}
