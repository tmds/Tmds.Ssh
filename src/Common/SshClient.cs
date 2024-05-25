// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

public sealed partial class SshClient : IDisposable
{
    public SshClient(string destination)
        : this(new SshClientSettings(destination))
    { }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        await _implementation.ConnectAsync(cancellationToken);
    }

    public void Dispose()
    {
        _implementation.Dispose();
    }

    public Task<RemoteProcess> ExecuteAsync(string command, CancellationToken cancellationToken)
        => ExecuteAsync(command, null, cancellationToken);

    public async Task<RemoteProcess> ExecuteAsync(string command, ExecuteOptions? options = null, CancellationToken cancellationToken = default)
    {
        var channel = await _implementation.OpenRemoteProcessChannelAsync(typeof(RemoteProcess), command, cancellationToken).ConfigureAwait(false);

        Encoding standardInputEncoding = options?.StandardInputEncoding ?? ExecuteOptions.DefaultEncoding;
        Encoding standardErrorEncoding = options?.StandardErrorEncoding ?? ExecuteOptions.DefaultEncoding;
        Encoding standardOutputEncoding = options?.StandardOutputEncoding ?? ExecuteOptions.DefaultEncoding;
        return new RemoteProcess(channel,
            standardInputEncoding,
            standardErrorEncoding,
            standardOutputEncoding);
    }

    public async Task<SshDataStream> OpenTcpConnectionAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        var channel = await _implementation.OpenTcpConnectionChannelAsync(typeof(SshDataStream), host, port, cancellationToken).ConfigureAwait(false);

        return new SshDataStream(channel);
    }

    public async Task<SshDataStream> OpenUnixConnectionAsync(string path, CancellationToken cancellationToken = default)
    {
        var channel = await _implementation.OpenUnixConnectionChannelAsync(typeof(SshDataStream), path, cancellationToken).ConfigureAwait(false);

        return new SshDataStream(channel);
    }

    public async Task<SftpClient> CreateSftpClientAsync(CancellationToken cancellationToken = default)
    {
        var channel = await _implementation.OpenSftpClientChannelAsync(typeof(SftpClient), cancellationToken).ConfigureAwait(false);

        var sftpClient = new SftpClient(channel);

        try
        {
            await sftpClient.ProtocolInitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            sftpClient.Dispose();

            throw;
        }

        return sftpClient;
    }
}
