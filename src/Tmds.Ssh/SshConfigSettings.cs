// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Runtime.CompilerServices;
using static System.Environment;

namespace Tmds.Ssh;

// Because we're a library the default of these options differs from the default 'ssh' command:
// - BatchMode=yes: not user interactive
// - ClearAllForwardings=yes: don't do any forwardings automatically
/// <summary>
/// Settings for configuring the SshClient using the OpenSSH ssh_config model.
/// </summary>
public sealed class SshConfigSettings
{
    /// <summary>
    /// Gets default configuration file paths.
    /// </summary>
    public static IReadOnlyList<string> DefaultConfigFilePaths { get; } = CreateDefaultConfigFilePaths();

    /// <summary>
    /// Gets default configuration settings.
    /// </summary>
    public static SshConfigSettings DefaultConfig { get; }= CreateDefault();

    /// <summary>
    /// Gets configuration that loads no files.
    /// </summary>
    public static SshConfigSettings NoConfig { get; }= CreateNoConfig();

    private bool _locked;

    private List<string>? _configFilePaths;
    private Dictionary<SshConfigOption, SshConfigOptionValue>? _options;
    private bool _autoConnect = true;
    private bool _autoReconnect = false;
    private TimeSpan _connectTimeout = SshClientSettings.DefaultConnectTimeout;
    private HostAuthentication? _hostAuthentication;
    private PasswordPrompt? _passwordPrompt;

    // Avoid allocations from the public getters.
    internal IReadOnlyList<string> ConfigFilePathsOrDefault
        => _configFilePaths ?? DefaultConfigFilePaths;
    internal IReadOnlyDictionary<SshConfigOption, SshConfigOptionValue>? OptionsOrDefault
        => _options;

    /// <summary>
    /// Creates default config settings.
    /// </summary>
    public SshConfigSettings()
    { }

    /// <summary>
    /// Gets or sets the config file paths.
    /// </summary>
    public List<string> ConfigFilePaths
    {
        get => _configFilePaths ??= new(DefaultConfigFilePaths);
        set
        {
            ThrowIfLocked();

            ArgumentNullException.ThrowIfNull(value);

            _configFilePaths = value;
        }
    }

    /// <summary>
    /// Gets or sets config options.
    /// </summary>
    public Dictionary<SshConfigOption, SshConfigOptionValue> Options
    {
        get => _options ??= new();
        set
        {
            ThrowIfLocked();

            ArgumentNullException.ThrowIfNull(value);

            _options = value;
        }
    }

    private static IReadOnlyDictionary<SshConfigOption, SshConfigOptionValue> ValidateOptions(IReadOnlyDictionary<SshConfigOption, SshConfigOptionValue> value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return value;
    }

    /// <summary>
    /// Gets or sets whether to automatically connect when the client is used.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="true"/>.
    /// </remarks>
    public bool AutoConnect
    {
        get => _autoConnect;
        set
        {
            ThrowIfLocked();

            _autoConnect = value;
        }
    }

    /// <summary>
    /// Gets or sets whether to automatically reconnect when the client is used after an unexpected disconnect.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="false"/>.
    /// </remarks>
    public bool AutoReconnect
    {
        get => _autoReconnect;
        set
        {
            ThrowIfLocked();

            _autoReconnect = value;
        }
    }

    /// <summary>
    /// Gets or sets the connection timeout.
    /// </summary>
    /// <remarks>
    /// Defaults to 15 seconds. This is overridden by the ConnectTimeout option (when set).
    /// </remarks>
    public TimeSpan ConnectTimeout
    {
        get => _connectTimeout;
        set
        {
            ThrowIfLocked();

            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
            _connectTimeout = value;
        }
    }

    /// <summary>
    /// Gets or sets the host authentication callback for unknown host keys.
    /// </summary>
    /// <remarks>
    /// The delegate is called for unknown keys when StrictHostKeyChecking is 'ask' (default).
    /// </remarks>
    public HostAuthentication? HostAuthentication
    {
        get => _hostAuthentication;
        set
        {
            ThrowIfLocked();

            _hostAuthentication = value;
        }
    }

    /// <summary>
    /// Gets or sets the password prompt for password authentication.
    /// </summary>
    public PasswordPrompt? PasswordPrompt
    {
        get => _passwordPrompt;
        set
        {
            ThrowIfLocked();

            _passwordPrompt = value;
        }
    }

    internal void Validate()
    {
        if (_configFilePaths is not null)
        {
            foreach (var item in _configFilePaths)
            {
                if (item is null)
                {
                    throw new ArgumentException($"{nameof(ConfigFilePaths)} contains 'null'.", $"{nameof(ConfigFilePaths)}");
                }
                if (!Path.IsPathRooted(item))
                {
                    throw new ArgumentException("Config file paths must be rooted.", $"{nameof(ConfigFilePaths)}");
                }
            }
        }
        if (_options is not null)
        {
            foreach (var item in _options)
            {
                if (!Enum.IsDefined(item.Key))
                {
                    throw new ArgumentException($"{nameof(Options)} contains unknown key '{item.Key}'.", $"{nameof(Options)}");
                }
                if (item.Value.IsEmpty)
                {
                    throw new ArgumentException($"{nameof(Options)} contains 'null' value for key '{item.Key}'.", $"{nameof(Options)}");
                }
            }
        }
    }

    private void Lock()
    {
        _locked = true;
    }

    private void ThrowIfLocked()
    {
        if (_locked)
        {
            throw new InvalidOperationException($"{nameof(SshConfigSettings)} can not be changed.");
        }
    }

    private static SshConfigSettings CreateDefault()
    {
        var config = new SshConfigSettings();

        config.Lock();

        return config;
    }

    private static SshConfigSettings CreateNoConfig()
    {
        var config = new SshConfigSettings()
        {
            ConfigFilePaths = []
        };

        config.Lock();

        return config;
    }

    private static IReadOnlyList<string> CreateDefaultConfigFilePaths()
    {
        string userConfigFilePath = Path.Combine(SshClientSettings.Home, ".ssh", "config");
        string systemConfigFilePath;
        if (Platform.IsWindows)
        {
            systemConfigFilePath = Path.Combine(Environment.GetFolderPath(SpecialFolder.CommonApplicationData, SpecialFolderOption.DoNotVerify), "ssh", "ssh_config");
        }
        else
        {
            systemConfigFilePath = "/etc/ssh/ssh_config";
        }

        return [userConfigFilePath, systemConfigFilePath];
    }
}