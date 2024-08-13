// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;

namespace Tmds.Ssh;

// This class gathers settings for SshClient in a separate object.
public sealed partial class SshClientSettings
{
    private int _port = DefaultPort;
    private string _hostName = "";
    private string _userName = "";
    private IReadOnlyList<Credential> _credentials = DefaultCredentials;
    private TimeSpan _connectTimeout = DefaultConnectTimeout;
    private IReadOnlyList<string> _userKnownHostsFilePaths = DefaultUserKnownHostsFilePaths;
    private IReadOnlyList<string> _globalKnownHostsFilePaths = DefaultGlobalKnownHostsFilePaths;

    public SshClientSettings()
    { }

    public SshClientSettings(string destination)
    {
        (string? username, string host, int? port) = ParseDestination(destination);

        _hostName = host;
        _userName = username ?? Environment.UserName;
        _port = port ?? DefaultPort;
    }

    internal static (string? user, string host, int? port) ParseDestination(string destination)
    {
        ArgumentNullException.ThrowIfNull(destination);

        string? user = null;
        string host = destination;
        int? port = null;

        host = destination;
        int colonPos = host.LastIndexOf(":");
        if (colonPos != -1)
        {
            port = int.Parse(host.Substring(colonPos + 1));
            host = host.Substring(0, colonPos);
        }
        int atPos = host.LastIndexOf("@");
        if (atPos != -1)
        {
            user = host.Substring(0, atPos);
            host = host.Substring(atPos + 1);
        }

        return (user, host, port);
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

    public string HostName
    {
        get => _hostName;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _hostName = value;
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

    public IReadOnlyList<string> UserKnownHostsFilePaths
    {
        get => _userKnownHostsFilePaths;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            foreach (var item in value)
            {
                ArgumentNullException.ThrowIfNullOrEmpty(item);
            }
            _userKnownHostsFilePaths = value;
        }
    }

    public IReadOnlyList<string> GlobalKnownHostsFilePaths
    {
        get => _globalKnownHostsFilePaths;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            foreach (var item in value)
            {
                ArgumentNullException.ThrowIfNullOrEmpty(item);
            }
            _globalKnownHostsFilePaths = value;
        }
    }

    public bool UpdateKnownHostsFileAfterAuthentication { get; set; } = false;

    public HostAuthentication? HostAuthentication { get; set; }

    public bool AutoConnect { get; set; } = true;

    public bool AutoReconnect { get; set; } = false;

    public bool HashKnownHosts { get; set; } = DefaultHashKnownHosts;

    public IReadOnlyDictionary<string, string>? EnvironmentVariables { get; set; }

    public int MinimumRSAKeySize { get; set; } = DefaultMinimumRSAKeySize; // TODO throw if <0.

    // Currently these settings are not exposed.
    internal List<Name> KeyExchangeAlgorithms { get; set; } = DefaultKeyExchangeAlgorithms;
    internal List<Name> ServerHostKeyAlgorithms { get; set; } = DefaultServerHostKeyAlgorithms;
    internal List<Name> PublicKeyAcceptedAlgorithms { get; set; } = DefaultPublicKeyAcceptedAlgorithms;
    internal List<Name> EncryptionAlgorithmsClientToServer { get; set; } = DefaultEncryptionAlgorithms;
    internal List<Name> EncryptionAlgorithmsServerToClient { get; set; } = DefaultEncryptionAlgorithms;
    internal List<Name> MacAlgorithmsClientToServer { get; set; } = DefaultMacAlgorithms;
    internal List<Name> MacAlgorithmsServerToClient { get; set; } = DefaultMacAlgorithms;
    internal List<Name> CompressionAlgorithmsClientToServer { get; set; } = DefaultCompressionAlgorithms;
    internal List<Name> CompressionAlgorithmsServerToClient { get; set; } = DefaultCompressionAlgorithms;
    internal List<Name> LanguagesClientToServer { get; set; } = EmptyList;
    internal List<Name> LanguagesServerToClient { get; set; } = EmptyList;
}
