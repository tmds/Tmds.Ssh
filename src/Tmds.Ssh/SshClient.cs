// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using Tmds.Ssh.Managed;
using SshClientImplementation = Tmds.Ssh.Managed.ManagedSshClient;

namespace Tmds.Ssh;

public sealed partial class SshClient : IDisposable
{
    private readonly
#if DEBUG
        ISshClientImplementation
#else
        SshClientImplementation
#endif
        _implementation;

    // For testing.
    internal SshClient(ManagedSshClientSettings settings)
    {
        _implementation = new SshClientImplementation(settings);
    }

    public SshClient(SshClientSettings clientSettings)
    {
        _implementation = new SshClientImplementation(clientSettings ?? throw new ArgumentNullException(nameof(clientSettings)));
    }
}
