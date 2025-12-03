// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Exception thrown when an SSH operation fails. The connection and channel can still be used.
/// </summary>
public class SshOperationException : SshException
{
    internal SshOperationException(string message) : base(message) { }
    internal SshOperationException(string message, System.Exception? inner) : base(message, inner) { }
}
