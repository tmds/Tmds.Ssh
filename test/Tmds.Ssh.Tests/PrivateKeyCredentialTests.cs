using System.Diagnostics;
using System.Security.Cryptography;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class PrivateKeyCredentialTests
{
    class ECDsaKeyCredential : PrivateKeyCredential
    {
        public ECDsaKeyCredential(ECCurve curve)
            : base((c) => ValueTask.FromResult(new Key(ECDsa.Create(curve))), "ECDsa")
        { }
    }

    private const string PrivateRsaKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    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
    aT1PXN88b9LAsAAAALdG1kc0BmZWRvcmE=
    -----END OPENSSH PRIVATE KEY-----
    """;

    private const string TestPassword = "Cafés";

    private readonly SshServer _sshServer;

    public PrivateKeyCredentialTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task CtorWithRawKey()
    {
        PrivateKeyCredential credential = new PrivateKeyCredential(PrivateRsaKey.ToArray());
        using var privateKey = await credential.LoadKeyAsync(default);
        Assert.NotNull(privateKey);
    }

    [Fact]
    public async Task Pkcs1RsaKey()
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "PEM", null, null);
            return new PrivateKeyCredential(localKey);
        }, async (c) => await c.ConnectAsync());
    }

    [Fact]
    public async Task FailPkcs1EncryptedRsaKey()
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "PEM", null, null);
            await RunBinary("openssl", "pkey", "-in", localKey, "-inform", "PEM", "-out", $"{localKey}.rsa", "-traditional", "-aes256", "-passout", $"pass:{TestPassword}");
            File.Move($"{localKey}.rsa", localKey, overwrite: true);
            return new PrivateKeyCredential(localKey, TestPassword);
        }, async (SshClient client) =>
        {
            var exc = await Assert.ThrowsAnyAsync<ConnectFailedException>(() => client.ConnectAsync());
            Assert.IsType<PrivateKeyLoadException>(exc.InnerException);
        });
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
    public async Task Ecdsa256InMemoryKey()
    {
        Name expectedalgorithm = new Name("ecdsa-sha2-nistp256"u8.ToArray());

        var credential = new ECDsaKeyCredential(ECCurve.NamedCurves.nistP256);
        using var privateKey = await credential.LoadKeyAsync(default);
        Assert.NotNull(privateKey);
        Assert.Single(privateKey.Algorithms);
        Assert.Equal(expectedalgorithm, privateKey.Algorithms[0]);
    }

    [Fact]
    public async Task Ecdsa384InMemoryKey()
    {
        Name expectedalgorithm = new Name("ecdsa-sha2-nistp384"u8.ToArray());

        var credential = new ECDsaKeyCredential(ECCurve.NamedCurves.nistP384);
        using var privateKey = await credential.LoadKeyAsync(default);
        Assert.NotNull(privateKey);
        Assert.Single(privateKey.Algorithms);
        Assert.Equal(expectedalgorithm, privateKey.Algorithms[0]);
    }

    [Fact]
    public async Task Ecdsa521InMemoryKey()
    {
        Name expectedalgorithm = new Name("ecdsa-sha2-nistp521"u8.ToArray());

        var credential = new ECDsaKeyCredential(ECCurve.NamedCurves.nistP521);
        using var privateKey = await credential.LoadKeyAsync(default);
        Assert.NotNull(privateKey);
        Assert.Single(privateKey.Algorithms);
        Assert.Equal(expectedalgorithm, privateKey.Algorithms[0]);
    }

    [Fact]
    public async Task FailEcdsaKeyWithInvalidCurve()
    {
        const string expected = "Curve 'brainpoolP256r1' is not known.";

        var credential = new ECDsaKeyCredential(ECCurve.NamedCurves.brainpoolP256r1);
        NotSupportedException exc = await Assert.ThrowsAsync<NotSupportedException>(async () => await credential.LoadKeyAsync(default));
        Assert.Equal(expected, exc.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("aes256-ctr")]
    public async Task OpenSshEd25519Key(string? cipher)
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFileEd25519, async (string localKey) =>
        {
            string? keyPass = string.IsNullOrWhiteSpace(cipher) ? null : TestPassword;
            await EncryptSshKey(localKey, "RFC4716", keyPass, cipher);

            return new PrivateKeyCredential(localKey, keyPass);
        }, async (c) => await c.ConnectAsync());
    }

    [Fact]
    public async Task OpenSshKeyPromptNotCalledForPlaintextKey()
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, (string localKey) =>
        {
            return Task.FromResult(new PrivateKeyCredential(localKey, () => throw new Exception("should not be called")));
        }, async (c) => await c.ConnectAsync());
    }

    [Fact]
    public async Task OpenSshKeyWithPrompt()
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "RFC4716", TestPassword, "aes256-ctr");
            return new PrivateKeyCredential(localKey, () => TestPassword);
        }, async (c) => await c.ConnectAsync());
    }

    [Fact]
    public async Task OpenSshKeyWithWhitespacePassword()
    {
        const string password = " ";
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "RFC4716", password, "aes256-ctr");

            return new PrivateKeyCredential(localKey, password);
        }, async (c) => await c.ConnectAsync());
    }

    [Fact]
    public async Task FailWithEncryptedKeyAndNoPassword()
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "RFC4716", "password", null);
            return new PrivateKeyCredential(localKey);
        }, async (SshClient client) =>
        {
            var exc = await Assert.ThrowsAnyAsync<ConnectFailedException>(() => client.ConnectAsync());
            Assert.IsType<PrivateKeyLoadException>(exc.InnerException);
        });
    }

    [Fact]
    public async Task FailWithEncryptedKeyAndIncorrectPassword()
    {
        await RunWithKeyConversion(_sshServer.TestUserIdentityFile, async (string localKey) =>
        {
            await EncryptSshKey(localKey, "RFC4716", "password", null);
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
                UserKnownHostsFilePaths = [ _sshServer.KnownHostsFilePath ],
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
