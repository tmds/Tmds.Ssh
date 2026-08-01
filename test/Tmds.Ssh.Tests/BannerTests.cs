using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class BannerServerTests
{
    private readonly SshServer _sshServer;

    public BannerServerTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task BannerHandler_ReceivesTheServerBanner()
    {
        List<string> banners = new();

        var settings = _sshServer.CreateSshClientSettings(s =>
            s.BannerHandler = context => banners.Add(context.Message));

        using var client = new SshClient(settings);
        await client.ConnectAsync();

        string banner = Assert.Single(banners);
        Assert.Contains("Authorized use only.", banner);
        Assert.Contains("Second line of the banner.", banner);
    }
}

public class BannerTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("Welcome.", "")]
    [InlineData("Welcome.", "en-US")]
    [InlineData("line one\r\nline two\r\n", "")]
    [InlineData("ünïcödé ✔", "nl-BE")]
    public void ParseBanner_ReadsMessage(string message, string languageTag)
    {
        using Packet packet = CreateBannerPacket(message, languageTag);
        var connectionInfo = new SshConnectionInfo() { HostName = "host", UserName = "user", Port = 22 };

        BannerMessageContext context = UserAuthContext.ParseBanner(packet, connectionInfo);

        Assert.Equal(message, context.Message);
        Assert.Same(connectionInfo, context.ConnectionInfo);
    }

    [Fact]
    public void ParseBanner_KeepsPrintableMessageVerbatim()
    {
        // Printable text, including the URL that Tailscale SSH check mode sends before it will
        // finish authenticating, is not changed by control character escaping.
        const string message = "# Tailscale SSH requires an additional check.\n"
            + "# To authenticate, visit: https://login.tailscale.com/a/0123456789ab\n";

        using Packet packet = CreateBannerPacket(message, languageTag: "");
        BannerMessageContext context = UserAuthContext.ParseBanner(packet, new SshConnectionInfo());

        Assert.Equal(message, context.Message);
    }

    [Fact]
    public void ParseBanner_RejectsTrailingData()
    {
        using Packet packet = CreateBannerPacket("Welcome.", "", addTrailingByte: true);

        Assert.Throws<InvalidDataException>(
            () => UserAuthContext.ParseBanner(packet, new SshConnectionInfo()));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("line one\r\n\tline two", "line one\r\n\tline two")]
    [InlineData("\0", "\\u0000")]
    [InlineData("\a", "\\u0007")]
    [InlineData("\u001b[2J", "\\u001B[2J")]
    [InlineData("\u007f", "\\u007F")]
    [InlineData("\u0085", "\\u0085")]
    public void EscapeControlCharacters_EscapesAsUnicodeHex(string message, string expected)
    {
        Assert.Equal(expected, UserAuthContext.EscapeControlCharacters(message));
    }

    private static Packet CreateBannerPacket(
        string message,
        string languageTag,
        bool addTrailingByte = false)
    {
        using var packet = new SequencePool().RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_BANNER);
        writer.WriteString(message);
        writer.WriteString(languageTag);
        if (addTrailingByte)
        {
            writer.WriteByte(0);
        }
        return packet.Move();
    }
}
