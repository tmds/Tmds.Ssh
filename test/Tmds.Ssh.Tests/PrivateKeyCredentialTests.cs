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
        string localKey = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.Copy(_sshServer.TestUserIdentityFile, localKey);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(localKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            await EncryptSshKey(localKey, "PEM", null, null);
            PrivateKeyCredential key;
            if (string.IsNullOrWhiteSpace(algo))
            {
                key = new PrivateKeyCredential(localKey);
            }
            else
            {
                await RunBinary("openssl", "pkey", "-in", localKey, "-inform", "PEM", "-out", $"{localKey}.rsa", "-traditional", $"-{algo}", "-passout", $"pass:{TestPassword}");
                File.Move($"{localKey}.rsa", localKey, overwrite: true);
                key = new PrivateKeyCredential(localKey, TestPassword);
            }

            var settings = new SshClientSettings(_sshServer.Destination)
            {
                KnownHostsFilePath = _sshServer.KnownHostsFilePath,
                Credentials = [ key ],
            };
            using var client = new SshClient(settings);

            await client.ConnectAsync();
        }
        finally
        {
            if (File.Exists(localKey))
            {
                File.Delete(localKey);
            }
        }
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
        string localKey = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.Copy(_sshServer.TestUserIdentityFile, localKey);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(localKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            await EncryptSshKey(localKey, "RFC4716", string.IsNullOrWhiteSpace(cipher) ? null : TestPassword, cipher);

            var key = string.IsNullOrWhiteSpace(cipher)
                ? new PrivateKeyCredential(localKey)
                : new PrivateKeyCredential(localKey, TestPassword);

            var settings = new SshClientSettings(_sshServer.Destination)
            {
                KnownHostsFilePath = _sshServer.KnownHostsFilePath,
                Credentials = [ key ],
            };
            using var client = new SshClient(settings);

            await client.ConnectAsync();
        }
        finally
        {
            if (File.Exists(localKey))
            {
                File.Delete(localKey);
            }
        }
    }

    [Theory]
    [InlineData("PEM")]
    [InlineData("RFC4716")]
    public async Task FailWithEncryptedKeyAndNoPassword(string format)
    {
        string localKey = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.Copy(_sshServer.TestUserIdentityFile, localKey);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(localKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            await EncryptSshKey(localKey, format, "password", null);
            var settings = new SshClientSettings(_sshServer.Destination)
            {
                KnownHostsFilePath = _sshServer.KnownHostsFilePath,
                Credentials = [ new PrivateKeyCredential(localKey) ],
            };
            using var client = new SshClient(settings);

            var exc = await Assert.ThrowsAnyAsync<ConnectFailedException>(() => client.ConnectAsync());
            Assert.IsType<PrivateKeyLoadException>(exc.InnerException);
        }
        finally
        {
            if (File.Exists(localKey))
            {
                File.Delete(localKey);
            }
        }
    }

    [Theory]
    [InlineData("PEM")]
    [InlineData("RFC4716")]
    public async Task FailWithEncryptedKeyAndIncorrectPassword(string format)
    {
        string localKey = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.Copy(_sshServer.TestUserIdentityFile, localKey);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(localKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            await EncryptSshKey(localKey, format, "password", null);
            var settings = new SshClientSettings(_sshServer.Destination)
            {
                KnownHostsFilePath = _sshServer.KnownHostsFilePath,
                Credentials = [ new PrivateKeyCredential(localKey, "invalid") ],
            };
            using var client = new SshClient(settings);

            var exc = await Assert.ThrowsAnyAsync<ConnectFailedException>(() => client.ConnectAsync());
            Assert.IsType<PrivateKeyLoadException>(exc.InnerException);
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
