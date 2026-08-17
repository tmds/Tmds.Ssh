// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Options for configuring SftpClient.
/// </summary>
public sealed partial class SftpClientOptions
{
    private int? _windowSize;

    /// <summary>
    /// Gets or sets the SSH channel window size in bytes.
    /// </summary>
    /// <remarks>
    /// <para>When <see langword="null"/> (the default), <see cref="SshClientSettings.DefaultWindowSize"/> is used.</para>
    /// <para>The window size controls the maximum amount of data that can be sent by the remote end before it must wait for acknowledgement.
    /// Larger values can improve throughput on high-latency or high-bandwidth links at the cost of higher memory usage per channel.</para>
    /// </remarks>
    public int? WindowSize
    {
        get => _windowSize;
        set
        {
            if (value.HasValue)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value.Value, 0);
            }
            _windowSize = value;
        }
    }

    // For testing.
    internal SftpExtension DisabledExtensions { get; set; }
}
