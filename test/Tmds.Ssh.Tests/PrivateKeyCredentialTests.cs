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

    public PrivateKeyCredentialTests(SshServer sshServer) : base()
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task OpenSshRsa()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFile);
    }

    [Fact]
    public async Task OpenSshEcdsa256()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFileEcdsa256);
    }

    [Fact]
    public async Task OpenSshEcdsa384()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFileEcdsa384);
    }

    [Fact]
    public async Task OpenSshEcdsa521()
    {
        await ConnectWithKey(_sshServer.TestUserIdentityFileEcdsa521);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("aes128")]
    [InlineData("aes192")]
    [InlineData("aes256")]
    public async Task Pkcs1RsaKey(string? algo)
    {
        await RunWithKeyConversion(async (string localKey) =>
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
    public async Task OpenSshRsaKey(string? cipher)
    {
        await RunWithKeyConversion(async (string localKey) =>
        {
            string? keyPass = string.IsNullOrWhiteSpace(cipher) ? null : TestPassword;
            await EncryptSshKey(localKey, "RFC4716", keyPass, cipher);

            return new PrivateKeyCredential(localKey, keyPass);
        }, async (c) => await c.ConnectAsync());
    }

    [Fact]
    public async Task OpenSshRsaKeyWithWhitespacePassword()
    {
        const string passphrase = " ";
        await RunWithKeyConversion(async (string localKey) =>
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
        await RunWithKeyConversion(async (string localKey) =>
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
        await RunWithKeyConversion(async (string localKey) =>
        {
            await EncryptSshKey(localKey, format, "password", null);
            return new PrivateKeyCredential(localKey, "invalid");
        }, async (SshClient client) =>
        {
            var exc = await Assert.ThrowsAnyAsync<ConnectFailedException>(() => client.ConnectAsync());
            Assert.IsType<PrivateKeyLoadException>(exc.InnerException);
        });
    }

    private async Task RunWithKeyConversion(Func<string, Task<PrivateKeyCredential>> convertKey, Func<SshClient, Task> test)
    {
        string localKey = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.Copy(_sshServer.TestUserIdentityFile, localKey);
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

    private async Task ConnectWithKey(string keyPath)
    {
        var settings = new SshClientSettings(_sshServer.Destination)
        {
            UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
            Credentials = [ new PrivateKeyCredential(keyPath) ],
        };
        using var client = new SshClient(settings);

        await client.ConnectAsync();
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
