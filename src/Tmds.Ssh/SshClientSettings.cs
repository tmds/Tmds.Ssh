// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// This class gathers settings for SshClient in a separate object.
public sealed partial class SshClientSettings
{
    private int _port = DefaultPort;
    private string _hostName = "";
    private string _userName = "";
    private List<Credential>? _credentials;
    private TimeSpan _connectTimeout = DefaultConnectTimeout;
    private TimeSpan _keepAliveInterval = TimeSpan.Zero;
    private int _keepAliveCountMax = 3;
    private List<string>? _userKnownHostsFilePaths;
    private List<string>? _globalKnownHostsFilePaths;
    private Dictionary<string, string>? _environmentVariables;

    // Avoid allocations from the public getters.
    internal IReadOnlyList<Credential> CredentialsOrDefault
        => _credentials ?? DefaultCredentials;
    internal IReadOnlyList<string> UserKnownHostsFilePathsOrDefault
        => _userKnownHostsFilePaths ?? DefaultUserKnownHostsFilePaths;
    internal IReadOnlyList<string> GlobalKnownHostsFilePathsOrDefault
        => _globalKnownHostsFilePaths ?? DefaultGlobalKnownHostsFilePaths;
    internal Dictionary<string, string>? EnvironmentVariablesOrDefault
        => _environmentVariables;

    public SshClientSettings() :
        this("")
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

    public List<Credential> Credentials
    {
        get => _credentials ??= new List<Credential>(DefaultCredentials);
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

    public int KeepAliveCountMax
    {
        get => _keepAliveCountMax;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 0);
            _keepAliveCountMax = value;
        }
    }

    public TimeSpan KeepAliveInterval
    {
        get => _keepAliveInterval;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _keepAliveInterval = value;
        }
    }

    internal void Validate()
    {
        if (_credentials is not null)
        {
            foreach (var item in _credentials)
            {
                if (item is null)
                {
                    throw new ArgumentException($"{nameof(Credentials)} contains 'null'." , $"{nameof(Credentials)}");
                }
            }
        }
        if (_userKnownHostsFilePaths is not null)
        {
            foreach (var item in _userKnownHostsFilePaths)
            {
                if (item is null)
                {
                    throw new ArgumentException($"{nameof(UserKnownHostsFilePaths)} contains 'null'." , $"{nameof(UserKnownHostsFilePaths)}");
                }
            }
        }
        if (_globalKnownHostsFilePaths is not null)
        {
            foreach (var item in _globalKnownHostsFilePaths)
            {
                if (item is null)
                {
                    throw new ArgumentException($"{nameof(GlobalKnownHostsFilePaths)} contains 'null'." , $"{nameof(GlobalKnownHostsFilePaths)}");
                }
            }
        }
        if (_environmentVariables is not null)
        {
            foreach (var item in _environmentVariables)
            {
                if (item.Key.Length == 0)
                {
                    throw new ArgumentException($"{nameof(EnvironmentVariables)} contains empty key." , $"{nameof(EnvironmentVariables)}");
                }
                if (item.Value is null)
                {
                    throw new ArgumentException($"{nameof(EnvironmentVariables)} contains 'null' value for key '{item.Key}'." , $"{nameof(EnvironmentVariables)}");
                }
            }
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

    public List<string> UserKnownHostsFilePaths
    {
        get => _userKnownHostsFilePaths ??= new List<string>(DefaultUserKnownHostsFilePaths);
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _userKnownHostsFilePaths = value;
        }
    }

    public List<string> GlobalKnownHostsFilePaths
    {
        get => _globalKnownHostsFilePaths ??= new List<string>(DefaultGlobalKnownHostsFilePaths);
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _globalKnownHostsFilePaths = value;
        }
    }

    public bool UpdateKnownHostsFileAfterAuthentication { get; set; } = false;

    public HostAuthentication? HostAuthentication { get; set; }

    public bool AutoConnect { get; set; } = true;

    public bool AutoReconnect { get; set; } = false;

    public bool HashKnownHosts { get; set; } = DefaultHashKnownHosts;

    public Dictionary<string, string>? EnvironmentVariables
    {
        get => _environmentVariables ??= new();
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _environmentVariables = value;
        }
    }

    public bool TcpKeepAlive { get; set; } = DefaultTcpKeepAlive;

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
