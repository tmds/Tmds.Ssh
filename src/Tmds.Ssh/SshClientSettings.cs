// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

// This class gathers settings for SshClient in a separate object.
public sealed partial class SshClientSettings
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
        int colonPos = host.LastIndexOf(":");
        if (colonPos != -1)
        {
            port = int.Parse(host.Substring(colonPos + 1));
            host = host.Substring(0, colonPos);
        }
        int atPos = host.LastIndexOf("@");
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

    public bool UpdateKnownHostsFile { get; set; } = false;

    public HostAuthentication? HostAuthentication { get; set; }

    public bool AutoConnect { get; set; } = true;

    public bool AutoReconnect { get; set; } = false;

    public static IReadOnlyList<Credential> DefaultCredentials { get; } = CreateDefaultCredentials();

    private static string DefaultKnownHostsFile
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify),
                        ".ssh",
                        "known_hosts");

    private static IReadOnlyList<Credential> CreateDefaultCredentials()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        return
        [
            // new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_ed25519")),
            // new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_ecdsa")),
            new PrivateKeyCredential(Path.Combine(home, ".ssh", "id_rsa"))
        ];
    }    


    // Internal.
    // Algorithms are in **order of preference**.
    internal List<Name> KeyExchangeAlgorithms { get; } = new List<Name>() { AlgorithmNames.EcdhSha2Nistp256, AlgorithmNames.EcdhSha2Nistp384, AlgorithmNames.EcdhSha2Nistp521 };
    internal List<Name> ServerHostKeyAlgorithms { get; } = new List<Name>() { AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.RsaSshSha2_512, AlgorithmNames.RsaSshSha2_256 };
    internal List<Name> EncryptionAlgorithmsClientToServer { get; } = new List<Name>() { AlgorithmNames.Aes256Gcm, AlgorithmNames.Aes128Gcm };
    internal List<Name> EncryptionAlgorithmsServerToClient { get; } = new List<Name>() { AlgorithmNames.Aes256Gcm, AlgorithmNames.Aes128Gcm };
    internal List<Name> MacAlgorithmsClientToServer { get; } = new List<Name>() { AlgorithmNames.HMacSha2_256 };
    internal List<Name> MacAlgorithmsServerToClient { get; } = new List<Name>() { AlgorithmNames.HMacSha2_256 };
    internal List<Name> CompressionAlgorithmsClientToServer { get; } = new List<Name>() { AlgorithmNames.None };
    internal List<Name> CompressionAlgorithmsServerToClient { get; } = new List<Name>() { AlgorithmNames.None };
    internal List<Name> LanguagesClientToServer { get; } = new List<Name>();
    internal List<Name> LanguagesServerToClient { get; } = new List<Name>();

    // For testing:
    internal delegate Task<SshConnection> EstablishConnectionAsyncDelegate(ILogger logger, SequencePool sequencePool, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct);
    internal EstablishConnectionAsyncDelegate EstablishConnectionAsync = SshSession.EstablishConnectionAsync;
    internal ExchangeProtocolVersionAsyncDelegate ExchangeProtocolVersionAsync = ProtocolVersionExchange.Default;
    internal ExchangeKeysAsyncDelegate ExchangeKeysAsync = KeyExchange.Default;
    internal AuthenticateUserAsyncDelegate AuthenticateUserAsync = UserAuthentication.Default;
    internal bool NoProtocolVersionExchange = false;
    internal bool NoKeyExchange = false;
    internal bool NoUserAuthentication = false;         
}
