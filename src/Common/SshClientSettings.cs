// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh;

public delegate ValueTask<KeyVerificationResult> KeyVerification(KeyVerificationResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken);

// This class gathers settings for SshClient in a separate object.
public sealed class SshClientSettings
{
    private int _port = 22;
    private string _host = "";
    private string _userName = "";
    private IReadOnlyList<Credential> _credentials = DefaultCredentials;
    private TimeSpan _connectTimeout = TimeSpan.FromSeconds(15);

    public SshClientSettings()
    { }

    public SshClientSettings(string destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ConfigureForDestination(destination);
    }

    internal void ConfigureForDestination(string destination)
    {
        string host = destination;
        int port = 22;
        int colonPos = host.IndexOf(":");
        if (colonPos != -1)
        {
            port = int.Parse(host.Substring(colonPos + 1));
            host = host.Substring(0, colonPos);
        }
        int atPos = host.IndexOf("@");
        string username;
        if (atPos != -1)
        {
            username = host.Substring(0, atPos);
            host = host.Substring(atPos + 1);
        }
        else
        {
            username = Environment.UserName;
        }

        UserName = username;
        Host = host;
        Port = port;
    }

    public string UserName
    {
        get => _userName;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _userName = value;
        }
    }

    public string Host
    {
        get => _host;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _host = value;
        }
    }

    public IReadOnlyList<Credential> Credentials
    {
        get => _credentials;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            foreach (var item in value)
            {
                ArgumentNullException.ThrowIfNull(item);
            }
            _credentials = value;
        }
    }

    public TimeSpan ConnectTimeout
    {
        get => _connectTimeout;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
            _connectTimeout = value;
        }
    }

    public int Port
    {
        get => _port;
        set
        {
            if (value < 1 || value > 0xFFFF)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            _port = value;
        }
    }

    public string? KnownHostsFilePath { get; set; } = DefaultKnownHostsFile;

    public bool CheckGlobalKnownHostsFile { get; set; } = true;

    public KeyVerification? KeyVerification { get; set; }

    public static IReadOnlyList<Credential> DefaultCredentials { get; } = CreateDefaultCredentials();

    private static IReadOnlyList<Credential> CreateDefaultCredentials()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        return
        [
            new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_ed25519")),
            new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_ecdsa")),
            new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_rsa")),
            new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_dsa")),
        ];
    }

    private static string DefaultKnownHostsFile
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify),
                        ".ssh",
                        "known_hosts");
}
