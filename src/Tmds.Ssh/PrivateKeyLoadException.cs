// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh;

sealed class PrivateKeyLoadException : SshConnectionException
{
    internal PrivateKeyLoadException(string filename, Exception exception)
        : base(FormatMessage(filename), exception)
    { }

    private static string FormatMessage(string filename)
        => $"Failed to load key from file '{filename}'.";
}
