// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class SshDataStream : Stream
{
    private readonly ISshChannel _channel;

    internal SshDataStream(ISshChannel channel)
    {
        _channel = channel;
    }

    public CancellationToken StreamAborted
        => _channel.ChannelAborted;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new System.NotSupportedException();

    public override long Position { get => throw new System.NotSupportedException(); set => throw new System.NotSupportedException(); }

    public override void Flush()
    { }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new System.NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new System.NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();
    }

    public override void Close()
    {
        Dispose(disposing: true);
    }

    protected override void Dispose(bool disposing)
    {
        _channel.Dispose();
    }

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

    public void WriteEof()
    {
        _channel.WriteEof();
    }

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

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
