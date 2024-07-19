// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Enumeration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;

namespace Tmds.Ssh;

partial class SshClientSettings
{
    private static readonly Name[] DefaultPreferredAuthentications =
        [
            AlgorithmNames.GssApiWithMic,
            AlgorithmNames.HostBased,
            AlgorithmNames.PublicKey,
            AlgorithmNames.KeyboardInteractive,
            AlgorithmNames.Password
        ];

    internal static async ValueTask<SshClientSettings> LoadFromConfigAsync(string destination, SshConfigOptions options, CancellationToken cancellationToken = default)
    {
        (string? userName, string host, int? port) = ParseDestination(destination);

        SshConfig sshConfig = await SshConfig.DetermineConfigForHost(userName, host, port, options.ConfigFilePaths, cancellationToken);

        List<Name> ciphers = DetermineAlgorithms(sshConfig.Ciphers, DefaultEncryptionAlgorithms, SupportedEncryptionAlgorithms);
        List<Name> hostKeyAlgorithms = DetermineAlgorithms(sshConfig.HostKeyAlgorithms, DefaultServerHostKeyAlgorithms, SupportedServerHostKeyAlgorithms);
        List<Name> kexAlgorithms = DetermineAlgorithms(sshConfig.KexAlgorithms, DefaultKeyExchangeAlgorithms, SupportedKeyExchangeAlgorithms);
        List<Name> macs = DetermineAlgorithms(sshConfig.Macs, DefaultMacAlgorithms, SupportedMacAlgorithms);
        List<Name> publicKeyAcceptedAlgorithms = DetermineAlgorithms(sshConfig.PublicKeyAcceptedAlgorithms, DefaultPublicKeyAcceptedAlgorithms, SupportedPublicKeyAcceptedAlgorithms);
        List<Name> compressionAlgorithms = sshConfig.Compression == true ? EnableCompressionAlgorithms : DisableCompressionAlgorithms;

        var settings = new SshClientSettings()
        {
            HostName = sshConfig.HostName ?? host,
            UserName = sshConfig.UserName ?? Environment.UserName,
            Port = sshConfig.Port ?? DefaultPort,
            UserKnownHostsFilePaths = sshConfig.UserKnownHostsFiles ?? DefaultUserKnownHostsFilePaths,
            GlobalKnownHostsFilePaths = sshConfig.GlobalKnownHostsFiles ?? DefaultGlobalKnownHostsFilePaths,
            ConnectTimeout = sshConfig.ConnectTimeout > 0 ? TimeSpan.FromSeconds(sshConfig.ConnectTimeout.Value) : DefaultConnectTimeout,
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
            Credentials = DetermineCredentials(sshConfig)
        };

        return settings;
    }

    private static IReadOnlyList<Credential> DetermineCredentials(SshConfig config)
    {
        bool addPubKeyCredentials = config.PubKeyAuthentication ?? true;
        bool addGssApiCredentials = config.GssApiAuthentication ?? false;

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
                        string? serverIdentity = config.GssApiServerIdentity;
                        credentials.Add(new KerberosCredential(credential: null, delegateCredential, serverIdentity));

                        addGssApiCredentials = false;
                    }
                }
                else if (algorithm == AlgorithmNames.PublicKey)
                {
                    if (addPubKeyCredentials)
                    {
                        IReadOnlyList<string> identityFiles = config.IdentityFiles as IReadOnlyList<string> ?? DefaultIdentityFiles;
                        foreach (var identityFile in identityFiles)
                        {
                            credentials.Add(new PrivateKeyCredential(identityFile));
                        }

                        addPubKeyCredentials = false;
                    }
                }
            }
        }

        return credentials;
    }

    internal static List<Name> DetermineAlgorithms(SshConfig.AlgorithmList? config, List<Name> defaultAlgorithms, List<Name> supportedAlgorithms)
    {
        if (!config.HasValue)
        {
            return defaultAlgorithms;
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

        static void AddDefaultAlgorithms(OrderedSet<Name> set, List<Name> algorithms)
        {
            foreach (var algo in algorithms)
            {
                set.Add(algo);
            }
        }

        static void AddConfigAlgorithms(OrderedSet<Name> set, Name[] algorithms, List<Name> supportedAlgorithms)
        {
            foreach (var algo in algorithms)
            {
                if (supportedAlgorithms.Contains(algo))
                {
                    set.Add(algo);
                }
            }
        }
    }
}
