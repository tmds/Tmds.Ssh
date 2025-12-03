// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Base class for SSH exceptions.
/// </summary>
public class SshException : System.Exception
{
    internal SshException(string message) : base(message) { }
    internal SshException(string message, System.Exception? inner) : base(message, inner) { }
}
