using System;
using Xunit;

using System.Threading.Tasks;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Tmds.Utils;
using System.Collections.Generic;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class GssapiTests : IDisposable
{
    private readonly SshServer _sshServer;
    private readonly string _tempCCacheFilePath;
    private readonly Dictionary<string, string> _kerberosEnvironment;
    private readonly FunctionExecutor _kerberosExecutor;

    public GssapiTests(SshServer sshServer) : base()
    {
        _sshServer = sshServer;
        _tempCCacheFilePath = Path.GetTempFileName();
        _kerberosEnvironment = new Dictionary<string, string>()
        {
            ["KRB5_CONFIG"] = sshServer.KerberosConfigFilePath,
            ["KRB5CCNAME"] = $"FILE:{_tempCCacheFilePath}",
        };

        _kerberosExecutor = new FunctionExecutor(
            o =>
            {
                foreach (KeyValuePair<string, string> env in _kerberosEnvironment)
                {
                    o.StartInfo.Environment[env.Key] = env.Value;
                }
                o.StartInfo.RedirectStandardError = true;
                o.OnExit = p =>
                {
                    if (p.ExitCode == 0)
                    {
                        return;
                    }

                    string stderr = p.StandardError.ReadToEnd();
                    string message = $"Function exit code failed with exit code: {p.ExitCode}{Environment.NewLine}{stderr}";
                    throw new Xunit.Sdk.XunitException(message);
                };
            }
        );
    }

    public void Dispose()
    {
        if (File.Exists(_tempCCacheFilePath))
        {
            File.Delete(_tempCCacheFilePath);
        }
    }

    [InlineData(false)]
    [InlineData(true)]
    [SkippableTheory]
    public async Task WithCredential(bool overrideSpn)
    {
        Skip.IfNot(SshServer.HasKerberos, reason: "Kerberos not available");

        // Default SPN is derived from the connection hostname. The test server
        // only works when localhost is part of the SPN.
        string connectionName;
        string? serviceName = null;
        if (overrideSpn)
        {
            connectionName = $"127.0.0.1:{_sshServer.ServerPort}";
            serviceName = "host/localhost";
        }
        else
        {
            connectionName = $"localhost:{_sshServer.ServerPort}";
        }

        await _kerberosExecutor.RunAsync(
            async (string[] args) =>
            {
                var credential = new NetworkCredential(args[3], args[4]);
                var settings = new SshClientSettings(args[0])
                {
                    KnownHostsFilePath = args[2],
                    Credentials = [ new GssapiWithMicCredential(credential, serviceName: args[1]) ],
                };
                using var client = new SshClient(settings);

                await client.ConnectAsync();
            },
            [ connectionName, serviceName ?? string.Empty, _sshServer.KnownHostsFilePath, _sshServer.TestKerberosCredential.UserName, _sshServer.TestKerberosCredential.Password ]
        );
    }

    [SkippableFact]
    public async Task WithInvalidCredential()
    {
        Skip.IfNot(SshServer.HasKerberos, reason: "Kerberos not available");

        await _kerberosExecutor.RunAsync(
            async (string[] args) =>
            {
                var settings = new SshClientSettings(args[0])
                {
                    KnownHostsFilePath = args[1],
                    Credentials = [ new GssapiWithMicCredential(new NetworkCredential(args[2], "invalid")) ],
                };
                using var client = new SshClient(settings);

                await Assert.ThrowsAnyAsync<SshConnectionException>(() => client.ConnectAsync());
            },
            [ $"localhost:{_sshServer.ServerPort}", _sshServer.KnownHostsFilePath, _sshServer.TestKerberosCredential.UserName ]
        );
    }

    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [SkippableTheory]
    public async Task WithCachedCredentialAndDelegation(bool useLocalUser, bool requestDelegate)
    {
        Skip.IfNot(SshServer.HasKerberos, reason: "Kerberos not available");

        var kinitStartInfo = new ProcessStartInfo()
        {
            FileName = "kinit",
            RedirectStandardInput = true,
        };
        foreach (KeyValuePair<string, string> env in _kerberosEnvironment)
        {
            kinitStartInfo.Environment[env.Key] = env.Value;
        }

        // macOS and FreeBSD ship with Heimdal which needs this arg to read from stdin.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
        {
            kinitStartInfo.ArgumentList.Add("--password-file=STDIN");
        }

        if (requestDelegate)
        {
            kinitStartInfo.ArgumentList.Add("-f");
        }
        kinitStartInfo.ArgumentList.Add(_sshServer.TestKerberosCredential.UserName);

        using (var kinit = Process.Start(kinitStartInfo))
        {
            Assert.NotNull(kinit);
            kinit.StandardInput.WriteLine(_sshServer.TestKerberosCredential.Password);
            kinit.WaitForExit();
            Assert.True(kinit.ExitCode == 0);
        }

        string userName = useLocalUser ? _sshServer.TestUser : _sshServer.TestKerberosCredential.UserName;
        await _kerberosExecutor.RunAsync(
            async (string[] args) =>
            {
                string userName = args[2];
                bool requestDelegate = bool.Parse(args[3]);

                var settings = new SshClientSettings(args[0])
                {
                    KnownHostsFilePath = args[1],
                    UserName = userName,
                    Credentials = [ new GssapiWithMicCredential(delegateCredential: requestDelegate) ],
                };
                using var client = new SshClient(settings);

                await client.ConnectAsync();

                {
                    using var process = await client.ExecuteAsync("whoami");
                    (string? stdout, string? stderr) = await process.ReadToEndAsStringAsync();
                    Assert.Equal(0, process.ExitCode);
                    Assert.Equal(userName, stdout?.Trim());
                }

                {
                    using var process = await client.ExecuteAsync("klist -f");
                    (string? stdout, string? stderr) = await process.ReadToEndAsStringAsync();

                    if (requestDelegate)
                    {
                        // Must have F (Forwardable and f (forwarded) flags
                        Assert.Matches(@"Flags:\s+(?=.*F)(?=.*f).+", stdout);
                        Assert.Equal(0, process.ExitCode);
                    }
                    else
                    {
                        Assert.Matches("No credentials cache found", stderr);
                        Assert.Equal(1, process.ExitCode);
                    }
                }
            },
            [ $"localhost:{_sshServer.ServerPort}", _sshServer.KnownHostsFilePath, userName, requestDelegate.ToString() ]
        );
    }
}
