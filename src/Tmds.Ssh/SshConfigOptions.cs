// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Runtime.CompilerServices;
using static System.Environment;

namespace Tmds.Ssh;

public sealed class SshConfigOptions
{
    public static IReadOnlyList<string> DefaultConfigFilePaths { get; } = CreateDefaultConfigFilePaths();
    public static SshConfigOptions DefaultConfig { get; }= CreateDefault();

    public static SshConfigOptions NoConfig { get; }= CreateNoConfig();

    private bool _locked;

    private IReadOnlyList<string> _configFilePaths;
    private bool _autoConnect = true;
    private bool _autoReconnect = false;
    private TimeSpan _connectTimeout = SshClientSettings.DefaultConnectTimeout;
    private HostAuthentication? _hostAuthentication;

    public SshConfigOptions(IReadOnlyList<string> configFilePaths)
    {
        _configFilePaths = ValidateConfigFilePaths(configFilePaths);
    }

    public IReadOnlyList<string> ConfigFilePaths
    {
        get => _configFilePaths;
        set
        {
            ThrowIfLocked();

            _configFilePaths = ValidateConfigFilePaths(value);
        }
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

    private IReadOnlyList<string> ValidateConfigFilePaths(IReadOnlyList<string> argument, [CallerArgumentExpression(nameof(argument))] string? paramName = null)
    {
        ArgumentNullException.ThrowIfNull(argument, paramName);

        foreach (var path in argument)
        {
            if (!Path.IsPathRooted(path))
            {
                throw new ArgumentException("Config file paths must be rooted.", paramName);
            }
        }

        return argument;
    }

    private void Lock()
    {
        _locked = true;
    }

    private void ThrowIfLocked()
    {
        if (_locked)
        {
            throw new InvalidOperationException($"{nameof(SshConfigOptions)} can not be changed.");
        }
    }

    private static SshConfigOptions CreateDefault()
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
        var config = new SshConfigOptions([userConfigFilePath, systemConfigFilePath]);

        config.Lock();

        return config;
    }

    private static SshConfigOptions CreateNoConfig()
    {
        var config = new SshConfigOptions(DefaultConfigFilePaths);

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