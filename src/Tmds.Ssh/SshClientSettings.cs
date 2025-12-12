// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Settings for configuring SshClient.
/// </summary>
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
    private AlgorithmList? _keyExchangeAlgorithms;
    private AlgorithmList? _serverHostKeyAlgorithms;
    private AlgorithmList? _publicKeyAcceptedAlgorithms;
    private AlgorithmList? _encryptionAlgorithmsClientToServer;
    private AlgorithmList? _encryptionAlgorithmsServerToClient;
    private AlgorithmList? _macAlgorithmsClientToServer;
    private AlgorithmList? _macAlgorithmsServerToClient;
    private AlgorithmList? _compressionAlgorithmsClientToServer;
    private AlgorithmList? _compressionAlgorithmsServerToClient;
    private AlgorithmList? _caSignatureAlgorithms;

    // Avoid allocations from the public getters.
    internal IReadOnlyList<Credential> CredentialsOrDefault
        => _credentials ?? DefaultCredentials;
    internal IReadOnlyList<string> UserKnownHostsFilePathsOrDefault
        => _userKnownHostsFilePaths ?? DefaultUserKnownHostsFilePaths;
    internal IReadOnlyList<string> GlobalKnownHostsFilePathsOrDefault
        => _globalKnownHostsFilePaths ?? DefaultGlobalKnownHostsFilePaths;
    internal Dictionary<string, string>? EnvironmentVariablesOrDefault
        => _environmentVariables;
    internal List<Name> KeyExchangeAlgorithmsOrDefault
        => _keyExchangeAlgorithms?.AsNameList(SupportedKeyExchangeAlgorithms) ?? DefaultKeyExchangeAlgorithms;
    internal List<Name> ServerHostKeyAlgorithmsOrDefault
        => _serverHostKeyAlgorithms?.AsNameList(SupportedServerHostKeyAlgorithms) ?? DefaultServerHostKeyAlgorithms;
    internal List<Name>? ClientKeyAlgorithmsOrDefault
        => _publicKeyAcceptedAlgorithms?.AsNameList(SupportedClientKeyAlgorithms) ?? DefaultClientKeyAlgorithms;
    internal List<Name> EncryptionAlgorithmsClientToServerOrDefault
        => _encryptionAlgorithmsClientToServer?.AsNameList(SupportedEncryptionAlgorithms) ?? DefaultEncryptionAlgorithms;
    internal List<Name> EncryptionAlgorithmsServerToClientOrDefault
        => _encryptionAlgorithmsServerToClient?.AsNameList(SupportedEncryptionAlgorithms) ?? DefaultEncryptionAlgorithms;
    internal List<Name> MacAlgorithmsClientToServerOrDefault
        => _macAlgorithmsClientToServer?.AsNameList(SupportedMacAlgorithms) ?? DefaultMacAlgorithms;
    internal List<Name> MacAlgorithmsServerToClientOrDefault
        => _macAlgorithmsServerToClient?.AsNameList(SupportedMacAlgorithms) ?? DefaultMacAlgorithms;
    internal List<Name> CompressionAlgorithmsClientToServerOrDefault
        => _compressionAlgorithmsClientToServer?.AsNameList(SupportedCompressionAlgorithms) ?? DefaultCompressionAlgorithms;
    internal List<Name> CompressionAlgorithmsServerToClientOrDefault
        => _compressionAlgorithmsServerToClient?.AsNameList(SupportedCompressionAlgorithms) ?? DefaultCompressionAlgorithms;
    internal List<Name> ServerHostKeyCertificateAlgorithmsOrDefault
        => _caSignatureAlgorithms?.AsNameList(SupportedServerHostKeyCertificateAlgorithms) ?? DefaultServerHostKeyCertificateAlgorithms;

    /// <summary>
    /// Creates default settings.
    /// </summary>
    public SshClientSettings() :
        this("", allowEmptyHostname: true)
    { }

    /// <summary>
    /// Creates settings for the specified destination.
    /// </summary>
    /// <param name="destination">The destination in format [user@]host[:port].</param>
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

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="Environment.UserName"/>.
    /// </remarks>
    public string UserName
    {
        get => _userName;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _userName = value;
        }
    }

    /// <summary>
    /// Gets or sets the hostname or IP address of the server.
    /// </summary>
    public string HostName
    {
        get => _hostName;
        set
        {
            ArgumentValidation.ValidateHost(value, allowEmpty: false, nameof(value));
            _hostName = value;
        }
    }

    /// <summary>
    /// Gets or sets the credentials for authentication.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="DefaultCredentials"/>.
    /// </remarks>
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

    /// <summary>
    /// Gets or sets the connection timeout.
    /// </summary>
    /// <remarks>
    /// Defaults to 15 seconds.
    /// </remarks>
    public TimeSpan ConnectTimeout
    {
        get => _connectTimeout;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
            _connectTimeout = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of keep-alive messages before disconnecting.
    /// </summary>
    /// <remarks>
    /// Defaults to 3.
    /// </remarks>
    public int KeepAliveCountMax
    {
        get => _keepAliveCountMax;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 0);
            _keepAliveCountMax = value;
        }
    }

    /// <summary>
    /// Gets or sets the interval between keep-alive messages.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="TimeSpan.Zero"/>.
    /// </remarks>
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

    /// <summary>
    /// Gets or sets the server port.
    /// </summary>
    /// <remarks>
    /// Defaults to 22.
    /// </remarks>
    public int Port
    {
        get => _port;
        set
        {
            ArgumentValidation.ValidatePort(value, allowZero: false, nameof(value));
            _port = value;
        }
    }

    /// <summary>
    /// Gets or sets the paths to user known hosts files.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="DefaultUserKnownHostsFilePaths"/>.
    /// </remarks>
    public List<string> UserKnownHostsFilePaths
    {
        get => _userKnownHostsFilePaths ??= new List<string>(DefaultUserKnownHostsFilePaths);
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _userKnownHostsFilePaths = value;
        }
    }

    /// <summary>
    /// Gets or sets the paths to global known hosts files.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="DefaultGlobalKnownHostsFilePaths"/>.
    /// </remarks>
    public List<string> GlobalKnownHostsFilePaths
    {
        get => _globalKnownHostsFilePaths ??= new List<string>(DefaultGlobalKnownHostsFilePaths);
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _globalKnownHostsFilePaths = value;
        }
    }

    /// <summary>
    /// Gets or sets whether to update the known hosts file after authentication.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="false"/>.
    /// </remarks>
    public bool UpdateKnownHostsFileAfterAuthentication { get; set; } = false;

    /// <summary>
    /// Gets or sets the <see cref="HostAuthentication"/> delegate.
    /// </summary>
    /// <remarks>
    /// This delegate is not called when the host key is known to be trusted or revoked.
    /// </remarks>
    public HostAuthentication? HostAuthentication { get; set; }

    /// <summary>
    /// Gets or sets whether to automatically connect when the client is used.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="true"/>.
    /// </remarks>
    public bool AutoConnect { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to automatically reconnect when the client is used after an unexpected disconnect.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="false"/>.
    /// </remarks>
    public bool AutoReconnect { get; set; } = false;

    /// <summary>
    /// Gets or sets whether to hash hostnames in the known hosts file.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="false"/>.
    /// </remarks>
    public bool HashKnownHosts { get; set; } = DefaultHashKnownHosts;

    /// <summary>
    /// Gets or sets whether to enable batch mode (no interactive prompts).
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="false"/>.
    /// </remarks>
    public bool BatchMode { get; set; } = false;

    /// <summary>
    /// Gets or sets whether to enable batch mode when console is redirected.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="true"/>.
    /// </remarks>
    public bool EnableBatchModeWhenConsoleIsRedirected { get; set; } = true;

    /// <summary>
    /// Gets or sets environment variables for all remote processes.
    /// </summary>
    public Dictionary<string, string> EnvironmentVariables
    {
        get => _environmentVariables ??= new();
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _environmentVariables = value;
        }
    }

    /// <summary>
    /// Gets or sets whether to enable TCP keep-alive.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="true"/>.
    /// </remarks>
    public bool TcpKeepAlive { get; set; } = DefaultTcpKeepAlive;

    /// <summary>
    /// Gets or sets the minimum RSA key size accepted for authentication.
    /// </summary>
    /// <remarks>
    /// Defaults to 2048.
    /// </remarks>
    public int MinimumRSAKeySize { get; set; } = DefaultMinimumRSAKeySize; // TODO throw if <0.

    /// <summary>
    /// Gets or sets the <see cref="Proxy"/> configuration for the connection.
    /// </summary>
    public Proxy? Proxy { get; set; } = null;

    /// <summary>
    /// Gets or sets the permitted key exchange algorithms in order of preference.
    /// </summary>
    public AlgorithmList KeyExchangeAlgorithms
    {
        get => _keyExchangeAlgorithms ??= new AlgorithmList(DefaultKeyExchangeAlgorithms);
        set => _keyExchangeAlgorithms = value;
    }

    /// <summary>
    /// Gets or sets the host key signature algorithms in order of preference.
    /// </summary>
    public AlgorithmList ServerHostKeyAlgorithms
    {
        get => _serverHostKeyAlgorithms ??= new AlgorithmList(DefaultServerHostKeyAlgorithms);
        set => _serverHostKeyAlgorithms = value;
    }

    /// <summary>
    /// Gets or sets the signature algorithms allowed for client key authentication.
    /// </summary>
    /// <remarks>
    /// This limits how <see cref="Credentials"/> can be used for authentication based on the key signature algorithms.
    /// When <see langword="null"/>, all supported algorithms are allowed.
    /// </remarks>
    public AlgorithmList? ClientKeyAlgorithms
    {
        get => _publicKeyAcceptedAlgorithms;
        set => _publicKeyAcceptedAlgorithms = value;
    }

    /// <summary>
    /// Gets or sets the permitted ciphers for client to server communication in order of preference.
    /// </summary>
    public AlgorithmList EncryptionAlgorithmsClientToServer
    {
        get => _encryptionAlgorithmsClientToServer ??= new AlgorithmList(DefaultEncryptionAlgorithms);
        set => _encryptionAlgorithmsClientToServer = value;
    }

    /// <summary>
    /// Gets or sets the permitted ciphers for server to client communication in order of preference.
    /// </summary>
    public AlgorithmList EncryptionAlgorithmsServerToClient
    {
        get => _encryptionAlgorithmsServerToClient ??= new AlgorithmList(DefaultEncryptionAlgorithms);
        set => _encryptionAlgorithmsServerToClient = value;
    }

    /// <summary>
    /// Gets or sets the permitted integrity algorithms for client to server communication in order of preference.
    /// </summary>
    public AlgorithmList MacAlgorithmsClientToServer
    {
        get => _macAlgorithmsClientToServer ??= new AlgorithmList(DefaultMacAlgorithms);
        set => _macAlgorithmsClientToServer = value;
    }

    /// <summary>
    /// Gets or sets the permitted integrity algorithms for server to client communication in order of preference.
    /// </summary>
    public AlgorithmList MacAlgorithmsServerToClient
    {
        get => _macAlgorithmsServerToClient ??= new AlgorithmList(DefaultMacAlgorithms);
        set => _macAlgorithmsServerToClient = value;
    }

    /// <summary>
    /// Gets or sets the permitted compression algorithms for client to server communication in order of preference.
    /// </summary>
    internal AlgorithmList CompressionAlgorithmsClientToServer
    {
        get => _compressionAlgorithmsClientToServer ??= new AlgorithmList(DefaultCompressionAlgorithms);
        set => _compressionAlgorithmsClientToServer = value;
    }

    /// <summary>
    /// Gets or sets the permitted compression algorithms for server to client communication in order of preference.
    /// </summary>
    internal AlgorithmList CompressionAlgorithmsServerToClient
    {
        get => _compressionAlgorithmsServerToClient ??= new AlgorithmList(DefaultCompressionAlgorithms);
        set => _compressionAlgorithmsServerToClient = value;
    }

    /// <summary>
    /// Gets or sets the permitted algorithms allowed for signing of certificates by certificate authorities (CAs).
    /// </summary>
    /// <remarks>
    /// The client will not accept host certificates signed using algorithms other than those specified.
    /// </remarks>
    public AlgorithmList ServerHostKeyCertificateAlgorithms
    {
        get => _caSignatureAlgorithms ??= new AlgorithmList(DefaultServerHostKeyCertificateAlgorithms);
        set => _caSignatureAlgorithms = value;
    }

    internal List<Name> LanguagesClientToServer { get; set; } = EmptyList;
    internal List<Name> LanguagesServerToClient { get; set; } = EmptyList;
}
