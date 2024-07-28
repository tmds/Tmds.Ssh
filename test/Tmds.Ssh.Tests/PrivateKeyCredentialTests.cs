using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class PrivateKeyCredentialTests
{
    private const string TestPassword = "Cafés";

    private readonly SshServer _sshServer;

    public PrivateKeyCredentialTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [InlineData(null)]
    [InlineData("aes128")]
    [InlineData("aes192")]
    [InlineData("aes256")]
    public async Task Pkcs1RsaKey(string? algo)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "PEM", null, null);

            if (string.IsNullOrWhiteSpace(algo))
            {
                return new PrivateKeyCredential(localKey);
            }

            await RunBinary("openssl", "pkey", "-in", localKey, "-inform", "PEM", "-out", $"{localKey}.rsa", "-traditional", $"-{algo}", "-passout", $"pass:{TestPassword}");
            File.Move($"{localKey}.rsa", localKey, overwrite: true);
            return  new PrivateKeyCredential(localKey, TestPassword);
        }, async (c) => await c.ConnectAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("aes128-cbc")]
    [InlineData("aes192-cbc")]
    [InlineData("aes256-cbc")]
    [InlineData("aes128-ctr")]
    [InlineData("aes192-ctr")]
    [InlineData("aes256-ctr")]
    [InlineData("aes128-gcm@openssh.com")]
    [InlineData("aes256-gcm@openssh.com")]
    [InlineData("chacha20-poly1305@openssh.com")]
    public async Task OpenSshRsaKey(string? cipher)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            string? keyPass = string.IsNullOrWhiteSpace(cipher) ? null : TestPassword;
            await EncryptSshKey(localKey, "RFC4716", keyPass, cipher);

            return new PrivateKeyCredential(localKey, keyPass);
        }, async (c) => await c.ConnectAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("aes256-ctr")]
    public async Task OpenSshEcdsa256Key(string? cipher)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFileEcdsa256, async (string localKey) =>
        {
            string? keyPass = string.IsNullOrWhiteSpace(cipher) ? null : TestPassword;
            await EncryptSshKey(localKey, "RFC4716", keyPass, cipher);

            return new PrivateKeyCredential(localKey, keyPass);
        }, async (c) => await c.ConnectAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("aes256-ctr")]
    public async Task OpenSshEcdsa384Key(string? cipher)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFileEcdsa384, async (string localKey) =>
        {
            string? keyPass = string.IsNullOrWhiteSpace(cipher) ? null : TestPassword;
            await EncryptSshKey(localKey, "RFC4716", keyPass, cipher);

            return new PrivateKeyCredential(localKey, keyPass);
        }, async (c) => await c.ConnectAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("aes256-ctr")]
    public async Task OpenSshEcdsa521Key(string? cipher)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFileEcdsa521, async (string localKey) =>
        {
            string? keyPass = string.IsNullOrWhiteSpace(cipher) ? null : TestPassword;
            await EncryptSshKey(localKey, "RFC4716", keyPass, cipher);

            return new PrivateKeyCredential(localKey, keyPass);
        }, async (c) => await c.ConnectAsync());
    }

    [Fact]
    public async Task OpenSshKeyWithWhitespacePassword()
    {
        const string passphrase = " ";
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "RFC4716", passphrase, "aes256-ctr");

            return new PrivateKeyCredential(localKey, passphrase);
        }, async (c) => await c.ConnectAsync());
    }

    [Theory]
    [InlineData("PEM")]
    [InlineData("RFC4716")]
    public async Task FailWithEncryptedKeyAndNoPassword(string format)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, format, "password", null);
            return new PrivateKeyCredential(localKey);
        }, async (SshClient client) =>
        {
            var exc = await Assert.ThrowsAnyAsync<ConnectFailedException>(() => client.ConnectAsync());
            Assert.IsType<PrivateKeyLoadException>(exc.InnerException);
        });
    }

    [Theory]
    [InlineData("PEM")]
    [InlineData("RFC4716")]
    public async Task FailWithEncryptedKeyAndIncorrectPassword(string format)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, format, "password", null);
            return new PrivateKeyCredential(localKey, "invalid");
        }, async (SshClient client) =>
        {
            var exc = await Assert.ThrowsAnyAsync<ConnectFailedException>(() => client.ConnectAsync());
            Assert.IsType<PrivateKeyLoadException>(exc.InnerException);
        });
    }

    private async Task RunWithKeyConversion(string keyFile, Func<string, Task<PrivateKeyCredential>> convertKey, Func<SshClient, Task> test)
    {
        string localKey = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.Copy(keyFile, localKey);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(localKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            PrivateKeyCredential key = await convertKey(localKey);
            var settings = new SshClientSettings(_sshServer.Destination)
            {
                KnownHostsFilePath = _sshServer.KnownHostsFilePath,
                Credentials = [ key ],
            };
            using var client = new SshClient(settings);

            await test(client);
        }
        finally
        {
            if (File.Exists(localKey))
            {
                File.Delete(localKey);
            }
        }
    }

    private static async Task EncryptSshKey(string filePath, string format, string? password, string? cipher)
    {
        List<string> sshKeygenArgs = new List<string>()
        {
            "-p", "-m", format, "-f", filePath, "-N", password ?? string.Empty
        };
        if (!string.IsNullOrWhiteSpace(cipher))
        {
            sshKeygenArgs.Add("-Z");
            sshKeygenArgs.Add(cipher);
        }
        await RunBinary("ssh-keygen", sshKeygenArgs.ToArray());
    }

    private static async Task RunBinary(string fileName, params string[] args)
    {
        var psi = new ProcessStartInfo()
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using var process = Process.Start(psi)!;
        await process.WaitForExitAsync();
        Assert.Equal(0, process.ExitCode);
    }
}
