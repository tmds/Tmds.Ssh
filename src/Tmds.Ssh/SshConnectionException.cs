// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Exception thrown when the connection becomes unusable.
/// </summary>
public class SshConnectionException : SshException
{
    internal SshConnectionException(string message) : base(message) { }
    internal SshConnectionException(string message, System.Exception? inner) : base(message, inner) { }
}
