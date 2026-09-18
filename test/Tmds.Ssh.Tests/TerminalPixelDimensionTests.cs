using Xunit;

namespace Tmds.Ssh.Tests;

public class TerminalPixelDimensionTests
{
    [Fact]
    public void ExecuteOptions_PixelDimensionsDefaultToZero()
    {
        var options = new ExecuteOptions();

        Assert.Equal(0, options.TerminalWidthPixels);
        Assert.Equal(0, options.TerminalHeightPixels);
    }

    [Fact]
    public void ExecuteOptions_PixelDimensionsAcceptZero()
    {
        var options = new ExecuteOptions
        {
            TerminalWidthPixels = 0,
            TerminalHeightPixels = 0
        };

        Assert.Equal(0, options.TerminalWidthPixels);
        Assert.Equal(0, options.TerminalHeightPixels);
    }

    [Fact]
    public void ExecuteOptions_RejectsNegativePixelDimensions()
    {
        var options = new ExecuteOptions();

        Assert.Throws<ArgumentOutOfRangeException>(() => options.TerminalWidthPixels = -1);
        Assert.Throws<ArgumentOutOfRangeException>(() => options.TerminalHeightPixels = -1);
        Assert.Equal(0, options.TerminalWidthPixels);
        Assert.Equal(0, options.TerminalHeightPixels);
    }

    [Fact]
    public void PtyRequest_WritesCharacterAndPixelDimensions()
    {
        using Packet packet = new SequencePool().CreateChannelPtyRequestMessage(
            remoteChannel: 7,
            term: "xterm-256color",
            columns: 100,
            rows: 30,
            widthPixels: 900,
            heightPixels: 540,
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
            columns: 80,
            rows: 24,
            widthPixels: 0,
            heightPixels: 0,
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
    }

    [Fact]
    public void WindowChange_WritesCharacterAndPixelDimensions()
    {
        using Packet packet = new SequencePool().CreateWindowChangeRequestMessage(
            remoteChannel: 3,
            columns: 100,
            rows: 30,
            widthPixels: 900,
            heightPixels: 540);

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
            columns: 100,
            rows: 30,
            widthPixels: 0,
            heightPixels: 0);

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
}
