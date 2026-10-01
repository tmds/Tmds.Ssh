using System.Text;
using Xunit;

namespace Tmds.Ssh.Tests;

public class TerminalSizeTests
{
    [Fact]
    public void ExecuteOptions_TerminalSizeDefaults()
    {
        var options = new ExecuteOptions();

        Assert.Equal(80, options.TerminalSize.Columns);
        Assert.Equal(24, options.TerminalSize.Rows);
        Assert.Equal(0, options.TerminalSize.WidthPixels);
        Assert.Equal(0, options.TerminalSize.HeightPixels);
    }

    [Fact]
    public void TerminalSize_AcceptsUnspecifiedPixels()
    {
        var size = new TerminalSize(80, 24, widthPixels: 0, heightPixels: 0);

        Assert.Equal(80, size.Columns);
        Assert.Equal(24, size.Rows);
        Assert.Equal(0, size.WidthPixels);
        Assert.Equal(0, size.HeightPixels);
    }

    [Fact]
    public void TerminalSize_RejectsZeroDimensions()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalSize(0, 24));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalSize(80, 0));
    }

    [Fact]
    public void TerminalSize_RejectsNegativeDimensions()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalSize(-1, 24));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalSize(80, -1));
    }

    [Fact]
    public void TerminalSize_RejectsNegativePixelDimensions()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalSize(80, 24, -1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalSize(80, 24, 0, -1));
    }

    [Fact]
    public void TerminalSize_Equality()
    {
        var size = new TerminalSize(80, 24, 800, 600);

        Assert.Equal(size, new TerminalSize(80, 24, 800, 600));

        Assert.NotEqual(size, new TerminalSize(81, 24, 800, 600));
        Assert.NotEqual(size, new TerminalSize(80, 25, 800, 600));
        Assert.NotEqual(size, new TerminalSize(80, 24, 801, 600));
        Assert.NotEqual(size, new TerminalSize(80, 24, 800, 601));
    }

    [Theory]
    [InlineData(80, 24, 0, 0, "80x24")]
    [InlineData(80, 24, 800, 600, "80x24 (800x600)")]
    [InlineData(80, 24, 800, 0, "80x24 (800x0)")]
    [InlineData(80, 24, 0, 600, "80x24 (0x600)")]
    public void TerminalSize_ToString(
        int columns,
        int rows,
        int widthPixels,
        int heightPixels,
        string expected)
    {
        var size = new TerminalSize(columns, rows, widthPixels, heightPixels);

        Assert.Equal(expected, size.ToString());
    }

    [Fact]
    public void PtyRequest_WritesCharacterAndPixelDimensions()
    {
        using Packet packet = new SequencePool().CreateChannelPtyRequestMessage(
            remoteChannel: 7,
            term: "xterm-256color",
            size: new TerminalSize(100, 30, 900, 540),
            terminalMode: [0]);

        SequenceReader reader = packet.GetReader();
        Assert.Equal(MessageId.SSH_MSG_CHANNEL_REQUEST, reader.ReadMessageId());
        Assert.Equal(7u, reader.ReadUInt32());
        Assert.Equal("pty-req", reader.ReadUtf8String());
        Assert.True(reader.ReadBoolean());
        Assert.Equal("xterm-256color", reader.ReadUtf8String());
        Assert.Equal(100u, reader.ReadUInt32());
        Assert.Equal(30u, reader.ReadUInt32());
        Assert.Equal(900u, reader.ReadUInt32());
        Assert.Equal(540u, reader.ReadUInt32());
        Assert.Equal(new byte[] { 0 }, reader.ReadStringAsByteArray());
        reader.ReadEnd();
    }

    [Fact]
    public void PtyRequest_UnspecifiedPixelsAreZero()
    {
        using Packet packet = new SequencePool().CreateChannelPtyRequestMessage(
            remoteChannel: 1,
            term: "xterm",
            size: new TerminalSize(80, 24),
            terminalMode: []);

        SequenceReader reader = packet.GetReader();
        reader.ReadMessageId();
        reader.SkipUInt32();
        reader.ReadUtf8String();
        reader.SkipBoolean();
        reader.ReadUtf8String();
        Assert.Equal(80u, reader.ReadUInt32());
        Assert.Equal(24u, reader.ReadUInt32());
        Assert.Equal(0u, reader.ReadUInt32());
        Assert.Equal(0u, reader.ReadUInt32());
        Assert.Empty(reader.ReadStringAsByteArray());
        reader.ReadEnd();
    }

    [Fact]
    public void WindowChange_WritesCharacterAndPixelDimensions()
    {
        using Packet packet = new SequencePool().CreateWindowChangeRequestMessage(
            remoteChannel: 3,
            size: new TerminalSize(100, 30, 900, 540));

        SequenceReader reader = packet.GetReader();
        Assert.Equal(MessageId.SSH_MSG_CHANNEL_REQUEST, reader.ReadMessageId());
        Assert.Equal(3u, reader.ReadUInt32());
        Assert.Equal("window-change", reader.ReadUtf8String());
        Assert.False(reader.ReadBoolean());
        Assert.Equal(100u, reader.ReadUInt32());
        Assert.Equal(30u, reader.ReadUInt32());
        Assert.Equal(900u, reader.ReadUInt32());
        Assert.Equal(540u, reader.ReadUInt32());
        reader.ReadEnd();
    }

    [Fact]
    public void WindowChange_UnspecifiedPixelsAreZero()
    {
        using Packet packet = new SequencePool().CreateWindowChangeRequestMessage(
            remoteChannel: 3,
            size: new TerminalSize(100, 30));

        SequenceReader reader = packet.GetReader();
        reader.ReadMessageId();
        reader.SkipUInt32();
        reader.ReadUtf8String();
        reader.SkipBoolean();
        Assert.Equal(100u, reader.ReadUInt32());
        Assert.Equal(30u, reader.ReadUInt32());
        Assert.Equal(0u, reader.ReadUInt32());
        Assert.Equal(0u, reader.ReadUInt32());
        reader.ReadEnd();
    }

    [Fact]
    public void TerminalSize_IsInitialTerminalSize()
    {
        using global::Tmds.Ssh.RemoteProcess process = CreateProcessWithTerminal(out _);

        Assert.Equal(80, process.TerminalSize.Columns);
        Assert.Equal(24, process.TerminalSize.Rows);
        Assert.Equal(0, process.TerminalSize.WidthPixels);
        Assert.Equal(0, process.TerminalSize.HeightPixels);
    }

    [Fact]
    public void SetTerminalSize_UpdatesTerminalSizeProperty()
    {
        using global::Tmds.Ssh.RemoteProcess process = CreateProcessWithTerminal(out _);

        Assert.True(process.SetTerminalSize(new TerminalSize(120, 40, 1200, 800)));
        Assert.Equal(120, process.TerminalSize.Columns);
        Assert.Equal(40, process.TerminalSize.Rows);
        Assert.Equal(1200, process.TerminalSize.WidthPixels);
        Assert.Equal(800, process.TerminalSize.HeightPixels);
    }

    [Fact]
    public void SetTerminalSize_WhenChannelIsClosed_DoesNotUpdateTerminalSize()
    {
        using global::Tmds.Ssh.RemoteProcess process = CreateProcessWithTerminal(out StubChannel channel);
        channel.ChangeTerminalSizeResult = false;

        Assert.False(process.SetTerminalSize(new TerminalSize(120, 40, 1200, 800)));
        Assert.Equal(80, process.TerminalSize.Columns);
        Assert.Equal(24, process.TerminalSize.Rows);
        Assert.Equal(0, process.TerminalSize.WidthPixels);
        Assert.Equal(0, process.TerminalSize.HeightPixels);
    }

    [Fact]
    public void SetTerminalSize_WithoutTerminalThrows()
    {
        using global::Tmds.Ssh.RemoteProcess process = CreateProcessWithoutTerminal();

        Assert.Throws<InvalidOperationException>(() => process.SetTerminalSize(new TerminalSize(80, 24)));
    }

    private static global::Tmds.Ssh.RemoteProcess CreateProcessWithTerminal(out StubChannel channel, TerminalSize? terminalSize = null)
    {
        channel = new StubChannel();
        return new(
            channel,
            Encoding.UTF8,
            Encoding.UTF8,
            Encoding.UTF8,
            hasTty: true,
            terminalSize: terminalSize ?? new TerminalSize(80, 24));
    }

    private static global::Tmds.Ssh.RemoteProcess CreateProcessWithoutTerminal() =>
        new(
            new StubChannel(),
            Encoding.UTF8,
            Encoding.UTF8,
            Encoding.UTF8,
            hasTty: false,
            terminalSize: default);

    private sealed class StubChannel : ISshChannel
    {
        public bool ChangeTerminalSizeResult { get; set; } = true;

        public int ReceiveMaxPacket => 32 * 1024;
        public int SendMaxPacket => 32 * 1024;
        public int WindowSize => 0;
        public CancellationToken ChannelAborted => CancellationToken.None;
        public int? ExitCode => null;
        public string? ExitSignal => null;
        public bool EofSent => false;

        public void Dispose() { }
        public void Abort(Exception exception) { }

        public ValueTask<(ChannelReadType ReadType, int BytesRead)> ReadAsync(
            Memory<byte>? stdoutBuffer,
            Memory<byte>? stderrBuffer,
            CancellationToken cancellationToken,
            bool forStream = false) =>
            throw new NotSupportedException();

        public ValueTask WriteAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken,
            bool forStream = false) =>
            throw new NotSupportedException();

        public void WriteEof(bool noThrow, bool forStream) { }

        public bool ChangeTerminalSize(TerminalSize size) => ChangeTerminalSizeResult;

        public bool SendSignal(string signalName) => true;

        public SshException CreateCloseException() => new("closed");
    }
}
