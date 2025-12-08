namespace Tmds.Ssh;

interface ISshChannel
{
    int ReceiveMaxPacket { get; }
    int SendMaxPacket { get; }
    CancellationToken ChannelAborted { get; }
    int? ExitCode { get; }
    string? ExitSignal { get; }
    bool EofSent { get; }

    void Dispose();
    void Abort(Exception exception);

    ValueTask<(ChannelReadType ReadType, int BytesRead)> ReadAsync
            (Memory<byte>? stdoutBuffer,
             Memory<byte>? stderrBuffer,
            CancellationToken cancellationToken,
            bool forStream = false);

    ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken, bool forStream = false);
    void WriteEof(bool noThrow, bool forStream);
    bool ChangeTerminalSize(int width, int height);
    bool SendSignal(string signalName);

    SshException CreateCloseException();
}