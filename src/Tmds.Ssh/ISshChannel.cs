namespace Tmds.Ssh;

interface ISshChannel
{
    int ReceiveMaxPacket { get; }
    int SendMaxPacket { get; }
    CancellationToken ChannelAborted { get; }
    int? ExitCode { get; }
    string? ExitSignal { get; }

    void Dispose();
    void Abort(Exception exception);

    ValueTask<(ChannelReadType ReadType, int BytesRead)> ReadAsync
            (Memory<byte>? stdoutBuffer = default,
             Memory<byte>? stderrBuffer = default,
            CancellationToken cancellationToken = default);

    ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
    void WriteEof(bool noThrow = false);
    void ChangeTerminalSize(int width, int height);

    Exception CreateCloseException();
}