// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using static System.Environment;

namespace Tmds.Ssh;

partial class SshClientSettings
{
    internal static readonly string Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);

    private static readonly string[] DefaultIdentityFiles =
    [
        Path.Combine(Home, ".ssh", "id_rsa")
    ];

    private const int DefaultPort = 22;

    public static IReadOnlyList<Credential> DefaultCredentials { get; } = CreateDefaultCredentials();

    public static IReadOnlyList<string> DefaultUserKnownHostsFilePaths { get; } =
    [
        Path.Combine(Home, ".ssh", "known_hosts")
    ];

    public static IReadOnlyList<string> DefaultGlobalKnownHostsFilePaths { get; } = CreateDefaultGlobalKnownHostsFilePaths();

    internal static TimeSpan DefaultConnectTimeout => TimeSpan.FromSeconds(15);

    private static int DefaultMinimumRSAKeySize => 2048;

    // Algorithms are in **order of preference**.
    private readonly static List<Name> EmptyList = [];
    internal readonly static List<Name> SupportedKeyExchangeAlgorithms = [ AlgorithmNames.EcdhSha2Nistp256, AlgorithmNames.EcdhSha2Nistp384, AlgorithmNames.EcdhSha2Nistp521 ];
    internal readonly static List<Name> SupportedServerHostKeyAlgorithms = [ AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.RsaSshSha2_512, AlgorithmNames.RsaSshSha2_256 ];
    internal readonly static List<Name> SupportedEncryptionAlgorithms = [ AlgorithmNames.Aes256Gcm, AlgorithmNames.Aes128Gcm ];
    internal readonly static List<Name> SupportedPublicKeyAcceptedAlgorithms = [ ..AlgorithmNames.SshRsaAlgorithms ];
    internal readonly static List<Name> SupportedMacAlgorithms = EmptyList;
    internal readonly static List<Name> SupportedCompressionAlgorithms = [ AlgorithmNames.None ];
    internal readonly static List<Name> DisableCompressionAlgorithms = [ AlgorithmNames.None ];
    internal readonly static List<Name> DefaultKeyExchangeAlgorithms = SupportedKeyExchangeAlgorithms;
    internal readonly static List<Name> DefaultServerHostKeyAlgorithms = SupportedServerHostKeyAlgorithms;
    internal readonly static List<Name> DefaultEncryptionAlgorithms = SupportedEncryptionAlgorithms;
    internal readonly static List<Name> DefaultPublicKeyAcceptedAlgorithms = SupportedPublicKeyAcceptedAlgorithms;
    internal readonly static List<Name> DefaultMacAlgorithms = SupportedMacAlgorithms;
    internal readonly static List<Name> DefaultCompressionAlgorithms = SupportedCompressionAlgorithms;
    internal readonly static List<Name> EnableCompressionAlgorithms = DisableCompressionAlgorithms; // no compression algorithms implemented.

    private static IReadOnlyList<Credential> CreateDefaultCredentials()
    {
        List<Credential> credentials = new();
        foreach (var identityFile in DefaultIdentityFiles)
        {
            new PrivateKeyCredential(identityFile);
        }
        credentials.Add(new KerberosCredential());
        return credentials.AsReadOnly();
    }

    private static IReadOnlyList<string> CreateDefaultGlobalKnownHostsFilePaths()
    {
        string path;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            path = Path.Combine(Environment.GetFolderPath(SpecialFolder.CommonApplicationData, SpecialFolderOption.DoNotVerify), "ssh", "known_hosts");
        }
        else
        {
            path = "/etc/ssh/known_hosts";
        }
        return
        [
            path
        ];
    }
}
