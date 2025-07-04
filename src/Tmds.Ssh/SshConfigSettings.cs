// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Runtime.CompilerServices;
using static System.Environment;

namespace Tmds.Ssh;

// Because we're a library the default of these options differs from the default 'ssh' command:
// - BatchMode=yes: not user interactive
// - ClearAllForwardings=yes: don't do any forwardings automatically
public sealed class SshConfigSettings
{
    public static IReadOnlyList<string> DefaultConfigFilePaths { get; } = CreateDefaultConfigFilePaths();
    public static SshConfigSettings DefaultConfig { get; }= CreateDefault();

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

    public SshConfigSettings()
    { }

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

    public bool AutoConnect
    {
        get => _autoConnect;
        set
        {
            ThrowIfLocked();

            _autoConnect = value;
        }
    }

    public bool AutoReconnect
    {
        get => _autoReconnect;
        set
        {
            ThrowIfLocked();

            _autoReconnect = value;
        }
    }

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

    // Called when StrictHostKeyChecking is Ask and the key is unknown.
    public HostAuthentication? HostAuthentication
    {
        get => _hostAuthentication;
        set
        {
            ThrowIfLocked();

            _hostAuthentication = value;
        }
    }

    // Prompt used for password authentication.
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