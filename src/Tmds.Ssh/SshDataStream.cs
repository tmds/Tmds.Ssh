// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// <see cref="Stream"/> for channel data.
/// </summary>
public sealed class SshDataStream : Stream
{
    private readonly ISshChannel _channel;

    internal SshDataStream(ISshChannel channel)
    {
        _channel = channel;
    }

    // OpenSSH uses the maximum packet sizes as how much data may fit into an SSH_MSG_CHANNEL_DATA packet.
    // We're following that behavior and don't subtract bytes for the header.
    internal int ReadMaxPacketDataLength => _channel.ReceiveMaxPacket;
    internal int WriteMaxPacketDataLength => _channel.SendMaxPacket;

    /// <summary>
    /// Gets a token canceled when the channel is aborted.
    /// </summary>
    public CancellationToken StreamAborted
        => _channel.ChannelAborted;

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => true;

    /// <inheritdoc />
    public override long Length => throw new System.NotSupportedException();

    /// <inheritdoc />
    public override long Position { get => throw new System.NotSupportedException(); set => throw new System.NotSupportedException(); }

    /// <inheritdoc />
    public override void Flush()
    { }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new System.NotSupportedException();
    }

    /// <inheritdoc />
    public override void SetLength(long value)
    {
        throw new System.NotSupportedException();
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public override void Close()
    {
        Dispose(disposing: true);
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        _channel.Dispose();
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(System.Memory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
    {
        try
        {
            while (true)
            {
                (ChannelReadType ReadType, int BytesRead) = await _channel.ReadAsync(buffer, default, cancellationToken).ConfigureAwait(false); ;
                switch (ReadType)
                {
                    case ChannelReadType.StandardOutput:
                        return BytesRead;
                    case ChannelReadType.Eof:
                        return 0;
                }
            }
        }
        catch (SshException ex)
        {
            // TODO: move IOException wrapping into SshChannel.ReadAsync
            throw new IOException($"Unable to transport data: {ex.Message}.", ex);
        }
    }

    /// <summary>
    /// Writes end-of-file.
    /// </summary>
    public void WriteEof()
    {
        _channel.WriteEof();
    }

    /// <inheritdoc />
    public override async ValueTask WriteAsync(System.ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
    {
        try
        {
            await _channel.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch (SshException ex)
        {
            // TODO: move IOException wrapping into SshChannel.WriteAsync
            throw new IOException($"Unable to transport data: {ex.Message}.", ex);
        }
    }

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
