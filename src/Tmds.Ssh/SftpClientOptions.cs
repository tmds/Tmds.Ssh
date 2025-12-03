// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Options for configuring SftpClient.
/// </summary>
public sealed partial class SftpClientOptions
{
    // For testing.
    internal SftpExtension DisabledExtensions { get; set; }
}
