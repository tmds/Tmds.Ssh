using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(BannerSshServerCollection))]
public class BannerServerTests
{
    private readonly BannerSshServer _sshServer;

    public BannerServerTests(BannerSshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task BannerHandler_ReceivesTheServerBanner()
    {
        List<string> banners = new();

        var settings = _sshServer.CreateSshClientSettings(s =>
            s.BannerHandler = (context, ct) =>
            {
                banners.Add(context.Message);
                return default;
            });

        using var client = new SshClient(settings);
        await client.ConnectAsync();

        string banner = Assert.Single(banners);
        Assert.Contains("Authorized use only.", banner);
        Assert.Contains("Second line of the banner.", banner);
    }

    [Fact]
    public async Task Connect_SucceedsWithoutABannerHandler()
    {
        // Banners are ignored when no handler is set; this is the pre-existing behaviour.
        using var client = new SshClient(_sshServer.CreateSshClientSettings());

        await client.ConnectAsync();
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
    public void ParseBanner_ReadsMessageAndLanguageTag(string message, string languageTag)
    {
        using Packet packet = CreateBannerPacket(message, languageTag);
        var connectionInfo = new SshConnectionInfo() { HostName = "host", UserName = "user", Port = 22 };

        BannerContext context = UserAuthContext.ParseBanner(packet, connectionInfo);

        Assert.Equal(message, context.Message);
        Assert.Equal(languageTag, context.LanguageTag);
        Assert.Same(connectionInfo, context.ConnectionInfo);
    }

    [Fact]
    public void ParseBanner_KeepsTheMessageVerbatim()
    {
        // The message is server-controlled and may carry anything, including the URL that
        // Tailscale SSH check mode sends before it will finish authenticating. Callers decide how
        // to render it; parsing must not alter it.
        const string message = "# Tailscale SSH requires an additional check.\n"
            + "# To authenticate, visit: https://login.tailscale.com/a/0123456789ab\n";

        using Packet packet = CreateBannerPacket(message, languageTag: "");
        BannerContext context = UserAuthContext.ParseBanner(packet, new SshConnectionInfo());

        Assert.Equal(message, context.Message);
    }

    private static Packet CreateBannerPacket(string message, string languageTag)
    {
        using var packet = new SequencePool().RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_USERAUTH_BANNER);
        writer.WriteString(message);
        writer.WriteString(languageTag);
        return packet.Move();
    }
}
