// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Collections;

namespace Tmds.Ssh;

partial class SshClientSettings
{
    private static readonly Name[] DefaultPreferredAuthentications =
        [
            AlgorithmNames.GssApiWithMic,
            AlgorithmNames.HostBased,
            AlgorithmNames.PublicKey,
            AlgorithmNames.KeyboardInteractive,
            AlgorithmNames.Password,
            AlgorithmNames.None
        ];

    internal static async ValueTask<SshClientSettings> LoadFromConfigAsync(string? userName, string host, int? port, SshConfigSettings options, CancellationToken cancellationToken = default)
    {
        SshConfig sshConfig = await SshConfig.DetermineConfigForHost(userName, host, port, options.OptionsOrDefault, options.ConfigFilePathsOrDefault, cancellationToken);

        List<Name> ciphers = DetermineAlgorithms(sshConfig.Ciphers, DefaultEncryptionAlgorithms, SupportedEncryptionAlgorithms);
        List<Name> hostKeyAlgorithms = DetermineAlgorithms(sshConfig.HostKeyAlgorithms, DefaultServerHostKeyAlgorithms, SupportedServerHostKeyAlgorithms);
        List<Name> kexAlgorithms = DetermineAlgorithms(sshConfig.KexAlgorithms, DefaultKeyExchangeAlgorithms, SupportedKeyExchangeAlgorithms);
        List<Name> macs = DetermineAlgorithms(sshConfig.Macs, DefaultMacAlgorithms, SupportedMacAlgorithms);
        List<Name> caSignatureAlgorithms = DetermineAlgorithms(sshConfig.CASignatureAlgorithms, DefaultCASignatureAlgorithms, SupportedCASignatureAlgorithms);
        List<Name> compressionAlgorithms = sshConfig.Compression == true ? EnableCompressionAlgorithms : DisableCompressionAlgorithms;
        List<Name>? publicKeyAcceptedAlgorithms =
            // Do not restrict if not specified.
            !sshConfig.PublicKeyAcceptedAlgorithms.HasValue ? null :
            // When set, use SupportedPublicKeyAlgorithms as the default set and permit adding unsupported algorithms that may be usable through the SSH Agent.
            DetermineAlgorithms(sshConfig.PublicKeyAcceptedAlgorithms, SupportedPublicKeyAlgorithms, null);

        var settings = new SshClientSettings()
        {
            HostName = sshConfig.HostName ?? host,
            UserName = sshConfig.UserName ?? Environment.UserName,
            Port = sshConfig.Port ?? DefaultPort,
            ConnectTimeout = sshConfig.ConnectTimeout > 0 ? TimeSpan.FromSeconds(sshConfig.ConnectTimeout.Value) : options.ConnectTimeout,
            KeyExchangeAlgorithms = kexAlgorithms,
            ServerHostKeyAlgorithms = hostKeyAlgorithms,
            PublicKeyAcceptedAlgorithms = publicKeyAcceptedAlgorithms,
            EncryptionAlgorithmsClientToServer = ciphers,
            EncryptionAlgorithmsServerToClient = ciphers,
            MacAlgorithmsClientToServer = macs,
            MacAlgorithmsServerToClient = macs,
            CompressionAlgorithmsClientToServer = compressionAlgorithms,
            CompressionAlgorithmsServerToClient = compressionAlgorithms,
            MinimumRSAKeySize = sshConfig.RequiredRSASize ?? DefaultMinimumRSAKeySize,
            Credentials = DetermineCredentials(sshConfig, options),
            HashKnownHosts = sshConfig.HashKnownHosts ?? DefaultHashKnownHosts,
            TcpKeepAlive = sshConfig.TcpKeepAlive ?? DefaultTcpKeepAlive,
            KeepAliveCountMax = sshConfig.ServerAliveCountMax ?? DefaultKeepAliveCountMax,
            KeepAliveInterval = sshConfig.ServerAliveInterval > 0 ? TimeSpan.FromSeconds(sshConfig.ServerAliveInterval.Value) : TimeSpan.Zero,
            Proxy = DetermineProxy(sshConfig.ProxyJump, options),
            BatchMode = sshConfig.BatchMode ?? false
        };
        if (sshConfig.UserKnownHostsFiles is not null)
        {
            settings.UserKnownHostsFilePaths = sshConfig.UserKnownHostsFiles;
        }
        if (sshConfig.GlobalKnownHostsFiles is not null)
        {
            settings.GlobalKnownHostsFilePaths = sshConfig.GlobalKnownHostsFiles;
        }
        var envvars = CreateEnvironmentVariables(Environment.GetEnvironmentVariables(), sshConfig.SendEnv);
        if (envvars is not null)
        {
            settings.EnvironmentVariables = envvars;
        }

        SshConfig.StrictHostKeyChecking hostKeyChecking = sshConfig.HostKeyChecking ?? SshConfig.StrictHostKeyChecking.Ask;
        switch (hostKeyChecking)
        {
            case SshConfig.StrictHostKeyChecking.No:
                settings.UpdateKnownHostsFileAfterAuthentication = true;
                // Allow unknown and changed.
                settings.HostAuthentication =
                    (HostAuthenticationContext context, CancellationToken cancellationToken)
                        => ValueTask.FromResult(context.KnownHostResult is KnownHostResult.Unknown or KnownHostResult.Changed);
                break;

            case SshConfig.StrictHostKeyChecking.AcceptNew:
                settings.UpdateKnownHostsFileAfterAuthentication = true;
                // Disallow changed. Allow unknown.
                settings.HostAuthentication =
                    (HostAuthenticationContext context, CancellationToken cancellationToken)
                        => ValueTask.FromResult(context.KnownHostResult == KnownHostResult.Unknown);
                break;

            case SshConfig.StrictHostKeyChecking.Ask:
                settings.UpdateKnownHostsFileAfterAuthentication = true;
                // Disallow changed, and ask for unknown keys.
                if (options.HostAuthentication is HostAuthentication authentication)
                {
                    settings.HostAuthentication =
                        (HostAuthenticationContext context, CancellationToken cancellationToken) =>
                        {
                            if (context.KnownHostResult == KnownHostResult.Changed)
                            {
                                return ValueTask.FromResult(false);
                            }
                            return authentication(context, cancellationToken);
                        };
                }
                else
                {
                    settings.HostAuthentication = delegate { return ValueTask.FromResult(false); };
                }
                break;

            case SshConfig.StrictHostKeyChecking.Yes:
            default:
                settings.UpdateKnownHostsFileAfterAuthentication = false;
                settings.HostAuthentication = delegate { return ValueTask.FromResult(false); };
                break;
        }

        return settings;
    }

    internal static Dictionary<string, string>? CreateEnvironmentVariables(IDictionary systemEnvironment, List<System.String>? sendEnv)
    {
        if (sendEnv is null || sendEnv.Count == 0)
        {
            return null;
        }

        Dictionary<string, string> envvars = new(StringComparer.Ordinal);

        foreach (DictionaryEntry de in systemEnvironment)
        {
            foreach (var pattern in sendEnv)
            {
                if (PatternMatcher.IsPatternMatch(pattern, (string)de.Key))
                {
                    envvars.Add((string)de.Key, (string)de.Value!);
                }
            }
        }

        return envvars;
    }

    private static List<Credential> DetermineCredentials(SshConfig config, SshConfigSettings options)
    {
        bool addPubKeyCredentials = config.PubKeyAuthentication ?? true && IsAcceptedAuthentication(AlgorithmNames.PublicKey);
        bool addGssApiCredentials = config.GssApiAuthentication ?? false && IsAcceptedAuthentication(AlgorithmNames.GssApiWithMic);
        bool assPasswordCredential = config.PasswordAuthentication ?? true && IsAcceptedAuthentication(AlgorithmNames.Password);
        bool addSshAgentCredentials = config.IdentitiesOnly != true && addPubKeyCredentials;
        bool addNone = IsAcceptedAuthentication(AlgorithmNames.None);

        ReadOnlySpan<Name[]> authPreferences = [
            config.PreferredAuthentications ?? Array.Empty<Name>(),
            DefaultPreferredAuthentications
        ];

        List<Credential> credentials = new();

        foreach (var preferredAuthentications in authPreferences)
        {
            foreach (var algorithm in preferredAuthentications)
            {
                if (algorithm == AlgorithmNames.GssApiWithMic)
                {
                    if (addGssApiCredentials)
                    {
                        bool delegateCredential = config.GssApiDelegateCredentials ?? false;
                        string? targetName = !string.IsNullOrEmpty(config.GssApiServerIdentity) ? $"host/{config.GssApiServerIdentity}" : null;
                        credentials.Add(new KerberosCredential(credential: null, delegateCredential, targetName));

                        addGssApiCredentials = false;
                    }
                }
                else if (algorithm == AlgorithmNames.PublicKey)
                {
                    if (addPubKeyCredentials)
                    {
                        SshAgentCredentials? sshAgentCredential = null;
                        if (addSshAgentCredentials)
                        {
                            sshAgentCredential = new SshAgentCredentials();
                            addSshAgentCredentials = false;
                        }
                        bool useDefaultIdentityFiles = config.IdentityFiles is null && config.CertificateFiles is null;
                        IReadOnlyList<string>? identityFiles = useDefaultIdentityFiles ? DefaultIdentityFiles : config.IdentityFiles;
                        if (config.CertificateFiles is not null)
                        {
                            if (config.IdentityFiles is not null || sshAgentCredential is not null)
                            {
                                foreach (var certificateFile in config.CertificateFiles)
                                {
                                    credentials.Add(new CertificateFileCredential(certificateFile, config.IdentityFiles, sshAgentCredential));
                                }
                            }
                        }
                        if (identityFiles is not null)
                        {
                            foreach (var identityFile in identityFiles)
                            {
                                PrivateKeyCredential privateKey = new PrivateKeyCredential(identityFile);
                                credentials.Add(privateKey);
                                credentials.Add(new CertificateCredential($"{identityFile}-cert.pub", privateKey));
                            }
                        }
                        if (sshAgentCredential is not null)
                        {
                            credentials.Add(sshAgentCredential);
                        }

                        addPubKeyCredentials = false;
                    }
                }
                else if (algorithm == AlgorithmNames.Password)
                {
                    if (assPasswordCredential)
                    {
                        if (options.PasswordPrompt is { } prompt)
                        {
                            credentials.Add(new PasswordCredential(prompt));
                        }

                        assPasswordCredential = false;
                    }
                }
                else if (algorithm == AlgorithmNames.None)
                {
                    if (addNone)
                    {
                        credentials.Add(new NoCredential());

                        addNone = false;
                    }
                }
            }
        }

        return credentials;

        bool IsAcceptedAuthentication(Name algorithm)
        {
            return config.PreferredAuthentications == null ||
                   config.PreferredAuthentications.Length == 0 ||
                   config.PreferredAuthentications.Contains(algorithm);
        }
    }

    // internal for tests.
    internal static List<Name> DetermineAlgorithms(SshConfig.AlgorithmList? config, IReadOnlyList<Name> defaultAlgorithms, IReadOnlyList<Name>? supportedAlgorithms)
    {
        if (!config.HasValue)
        {
            return new List<Name>(defaultAlgorithms);
        }

        SshConfig.AlgorithmList configAlgorithms = config.Value;

        switch (configAlgorithms.Operation)
        {
            case SshConfig.AlgorithmListOperation.Prepend:
            {
                OrderedSet<Name> algorithms = new(defaultAlgorithms.Count + configAlgorithms.Algorithms.Length);
                AddConfigAlgorithms(algorithms, configAlgorithms.Algorithms, supportedAlgorithms);
                AddDefaultAlgorithms(algorithms, defaultAlgorithms);
                return algorithms.List;
            }
            case SshConfig.AlgorithmListOperation.Append:
            {
                OrderedSet<Name> algorithms = new(defaultAlgorithms.Count + configAlgorithms.Algorithms.Length);
                AddDefaultAlgorithms(algorithms, defaultAlgorithms);
                AddConfigAlgorithms(algorithms, configAlgorithms.Algorithms, supportedAlgorithms);
                return algorithms.List;
            }
            case SshConfig.AlgorithmListOperation.Remove:
            {
                List<Name> algorithms = new(defaultAlgorithms.Count);
                foreach (var algo in defaultAlgorithms)
                {
                    string s = algo.ToString();
                    if (!PatternMatcher.IsPatternListMatch(configAlgorithms.PatternList, s))
                    {
                        algorithms.Add(algo);
                    }
                }
                return algorithms;
            }
            case SshConfig.AlgorithmListOperation.Set:
            {
                OrderedSet<Name> algorithms = new(configAlgorithms.Algorithms.Length);
                AddConfigAlgorithms(algorithms, configAlgorithms.Algorithms, supportedAlgorithms);
                return algorithms.List;
            }
            case SshConfig.AlgorithmListOperation.Filter:
            {
                List<Name> algorithms = new(defaultAlgorithms.Count);
                foreach (var algo in defaultAlgorithms)
                {
                    string s = algo.ToString();
                    if (PatternMatcher.IsPatternListMatch(configAlgorithms.PatternList, s))
                    {
                        algorithms.Add(algo);
                    }
                }
                return algorithms;
            }
            default:
                throw new IndexOutOfRangeException();
        }

        static void AddDefaultAlgorithms(OrderedSet<Name> set, IReadOnlyList<Name> algorithms)
        {
            foreach (var algo in algorithms)
            {
                set.Add(algo);
            }
        }

        static void AddConfigAlgorithms(OrderedSet<Name> set, Name[] algorithms, IReadOnlyList<Name>? supportedAlgorithms)
        {
            foreach (var algo in algorithms)
            {
                if (supportedAlgorithms is null || supportedAlgorithms.Contains(algo))
                {
                    set.Add(algo);
                }
            }
        }
    }

    private static Proxy? DetermineProxy(string? proxyJump, SshConfigSettings options)
    {
        if (string.IsNullOrEmpty(proxyJump))
        {
            return null;
        }

        List<Proxy> jumpProxies = new();

        List<string> configFilePaths = options.ConfigFilePathsOrDefault.ToList();

        string[] jumpHosts = proxyJump.Split(',');
        bool isFirst = true;
        foreach (var jumpHost in jumpHosts)
        {
            var config = new SshConfigSettings()
            {
                ConfigFilePaths = configFilePaths,
                ConnectTimeout = options.ConnectTimeout,
                HostAuthentication = options.HostAuthentication
            };

            if (!isFirst)
            {
                // Ignore proxy jump config from ssh_config and directly use the previous Proxy in the chain.
                config.Options[SshConfigOption.ProxyJump] = "none";
            }
            isFirst = false;

            jumpProxies.Add(new SshProxy(jumpHost, config));
        }

        return Proxy.Chain(jumpProxies.ToArray());
    }
}
