// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SshClientImplementation = Tmds.Ssh.Libssh.LibsshSshClient;

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

    public SshClient(SshClientSettings clientSettings)
    {
        _implementation = new SshClientImplementation(clientSettings ?? throw new ArgumentNullException(nameof(clientSettings)));
    }
}
