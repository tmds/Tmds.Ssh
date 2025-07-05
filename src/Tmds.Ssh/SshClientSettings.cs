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
        this("", allowEmptyHostname: true)
    { }

    public SshClientSettings(string destination) :
        this(destination, allowEmptyHostname: false)
    { }

    private SshClientSettings(string destination, bool allowEmptyHostname)
    {
        (string? username, string host, int? port) = ParseDestination(destination, allowEmptyHostname);

        _hostName = host;
        _userName = username ?? Environment.UserName;
        _port = port ?? DefaultPort;
    }

    internal static (string? user, string host, int? port) ParseDestination(string destination, bool allowEmptyHostname = false)
    {
        ArgumentNullException.ThrowIfNull(destination);

        string? user = null;
        int? port = null;
        string host;
        if (destination.StartsWith("ssh://", StringComparison.InvariantCulture))
        {
            // ssh uris are defined in https://datatracker.ietf.org/doc/html/draft-ietf-secsh-scp-sftp-ssh-uri-04
            if (!Uri.TryCreate(destination, UriKind.Absolute, out Uri? uri))
            {
                throw new FormatException($"SSH URI '{destination}' is not a valid URI.");
            }
            port = uri.IsDefaultPort ? DefaultPort : uri.Port;
            host = uri.IdnHost;
            if (host.Length == 0)
            {
                throw new ArgumentException("SSH URI includes no hostname.", nameof(destination));
            }
            ReadOnlySpan<char> userSpan = uri.UserInfo;
            if (userSpan.Length > 0)
            {
                int delimPos = userSpan.IndexOf(';');
                if (delimPos != -1)
                {
                    userSpan = userSpan.Slice(0, delimPos);
                }
                if (userSpan.Contains(':'))
                {
                    throw new ArgumentException("SSH URI must not include a password.", nameof(destination));
                }
                if (userSpan.Length > 0)
                {
                    user = userSpan.ToString();
                }
            }
            if (uri.AbsolutePath != "/")
            {
                 throw new ArgumentException("SSH URI must not include a path.", nameof(destination));
            }
            if (uri.Query.Length > 0)
            {
                throw new ArgumentException("SSH URI must not include a query.", nameof(destination));
            }
            if (uri.Fragment.Length > 0)
            {
                throw new ArgumentException("SSH URI must not include a fragment.", nameof(destination));
            }
        }
        else
        {
            ReadOnlySpan<char> span = destination.AsSpan();
            // Anything before the last '@' is considered the user.
            int atPos = destination.LastIndexOf("@");
            if (atPos != -1)
            {
                user = destination.Substring(0, atPos);
                span = span.Slice(atPos + 1);
            }

            // Host is an IPv6 address.
            if (span.Length > 0 && span[0] == '[')
            {
                int endOfIPv6Address = span.IndexOf(']');
                if (endOfIPv6Address == -1)
                {
                    throw new FormatException($"IPv6 address in '{destination}' is not terminated by ']'.");
                }
                host = span.Slice(1, endOfIPv6Address - 1).ToString();
                span = span.Slice(endOfIPv6Address + 1);
            }
            else
            {
                int colonPos = span.LastIndexOf(":");
                if (colonPos == -1)
                {
                    colonPos = span.Length;
                }
                host = span.Slice(0, colonPos).ToString();
                span = span.Slice(colonPos);
            }
            if (span.Length > 0)
            {
                if (span[0] != ':' || !int.TryParse(span.Slice(1), out int portValue))
                {
                    throw new FormatException($"Can not parse port number from '{destination}'.");
                }
                ArgumentValidation.ValidatePort(portValue, allowZero: false, nameof(destination));
                port = portValue;
            }
            ArgumentValidation.ValidateHost(host, allowEmptyHostname, nameof(destination));
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
            ArgumentValidation.ValidateHost(value, allowEmpty: false, nameof(value));
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
        if (_hostName is null)
        {
            throw new ArgumentException($"{nameof(HostName)} contains 'null'.", $"{nameof(HostName)}");
        }
        if (_credentials is not null)
        {
            foreach (var item in _credentials)
            {
                if (item is null)
                {
                    throw new ArgumentException($"{nameof(Credentials)} contains 'null'.", $"{nameof(Credentials)}");
                }
            }
        }
        if (_userKnownHostsFilePaths is not null)
        {
            foreach (var item in _userKnownHostsFilePaths)
            {
                if (item is null)
                {
                    throw new ArgumentException($"{nameof(UserKnownHostsFilePaths)} contains 'null'.", $"{nameof(UserKnownHostsFilePaths)}");
                }
            }
        }
        if (_globalKnownHostsFilePaths is not null)
        {
            foreach (var item in _globalKnownHostsFilePaths)
            {
                if (item is null)
                {
                    throw new ArgumentException($"{nameof(GlobalKnownHostsFilePaths)} contains 'null'.", $"{nameof(GlobalKnownHostsFilePaths)}");
                }
            }
        }
        if (_environmentVariables is not null)
        {
            foreach (var item in _environmentVariables)
            {
                if (item.Key.Length == 0)
                {
                    throw new ArgumentException($"{nameof(EnvironmentVariables)} contains empty key.", $"{nameof(EnvironmentVariables)}");
                }
                if (item.Value is null)
                {
                    throw new ArgumentException($"{nameof(EnvironmentVariables)} contains 'null' value for key '{item.Key}'.", $"{nameof(EnvironmentVariables)}");
                }
            }
        }
    }

    internal SshClientSettings CreateSettingsForProxy(string destination)
    {
        SshClientSettings settings = new SshClientSettings(destination)
        {
            ConnectTimeout = ConnectTimeout,
        };

        // Credentials.
        if (_credentials is not null)
        {
            settings.Credentials = Credentials;
        }

        // Host auth.
        settings.HostAuthentication = HostAuthentication;
        if (_globalKnownHostsFilePaths is not null)
        {
            settings.GlobalKnownHostsFilePaths = GlobalKnownHostsFilePaths;
        }
        if (_userKnownHostsFilePaths is not null)
        {
            settings.UserKnownHostsFilePaths = UserKnownHostsFilePaths;
        }
        settings.UpdateKnownHostsFileAfterAuthentication = UpdateKnownHostsFileAfterAuthentication;

        return settings;
    }

    public int Port
    {
        get => _port;
        set
        {
            ArgumentValidation.ValidatePort(value, allowZero: false, nameof(value));
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

    public bool BatchMode { get; set; } = false;

    public bool EnableBatchModeWhenConsoleIsRedirected { get; set; } = true;

    public Dictionary<string, string> EnvironmentVariables
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

    public Proxy? Proxy { get; set; } = null;

    // Currently these settings are not exposed.
    internal List<Name> KeyExchangeAlgorithms { get; set; } = DefaultKeyExchangeAlgorithms;
    internal List<Name> ServerHostKeyAlgorithms { get; set; } = DefaultServerHostKeyAlgorithms;
    internal List<Name>? PublicKeyAcceptedAlgorithms { get; set; } = null; // Do not restrict.
    internal List<Name> EncryptionAlgorithmsClientToServer { get; set; } = DefaultEncryptionAlgorithms;
    internal List<Name> EncryptionAlgorithmsServerToClient { get; set; } = DefaultEncryptionAlgorithms;
    internal List<Name> MacAlgorithmsClientToServer { get; set; } = DefaultMacAlgorithms;
    internal List<Name> MacAlgorithmsServerToClient { get; set; } = DefaultMacAlgorithms;
    internal List<Name> CompressionAlgorithmsClientToServer { get; set; } = DefaultCompressionAlgorithms;
    internal List<Name> CompressionAlgorithmsServerToClient { get; set; } = DefaultCompressionAlgorithms;
    internal List<Name> LanguagesClientToServer { get; set; } = EmptyList;
    internal List<Name> LanguagesServerToClient { get; set; } = EmptyList;
    internal List<Name> CASignatureAlgorithms { get; set; } = DefaultCASignatureAlgorithms;
}
