// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using System.Security.Cryptography;
using static System.Environment;

namespace Tmds.Ssh;

partial class SshClientSettings
{
    internal static readonly string Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);

    private static readonly string[] DefaultIdentityFiles =
    [
        Path.Combine(Home, ".ssh", "id_ed25519"),
        Path.Combine(Home, ".ssh", "id_ecdsa"),
        Path.Combine(Home, ".ssh", "id_rsa"),
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

    private static bool DefaultHashKnownHosts => false;

    private static bool DefaultTcpKeepAlive => true;

    private static int DefaultKeepAliveCountMax => 3;

    // Algorithms are in **order of preference**.
    private readonly static List<Name> EmptyList = [];
    internal readonly static List<Name> SupportedKeyExchangeAlgorithms = [AlgorithmNames.SNtruP761X25519Sha512, AlgorithmNames.SNtruP761X25519Sha512OpenSsh, AlgorithmNames.Curve25519Sha256, AlgorithmNames.Curve25519Sha256LibSsh, AlgorithmNames.EcdhSha2Nistp256, AlgorithmNames.EcdhSha2Nistp384, AlgorithmNames.EcdhSha2Nistp521];
    internal readonly static List<Name> SupportedServerHostKeyAlgorithms = [ AlgorithmNames.SshEd25519, AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.RsaSshSha2_512, AlgorithmNames.RsaSshSha2_256 ];
    internal readonly static List<Name> SupportedEncryptionAlgorithms = CreatePreferredEncryptionAlgorithms();
    internal readonly static IReadOnlyList<Name> SupportedPublicKeyAlgorithms = [ AlgorithmNames.SshEd25519, AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.RsaSshSha2_512, AlgorithmNames.RsaSshSha2_256 ];
    internal readonly static List<Name> SupportedMacAlgorithms = EmptyList;
    internal readonly static List<Name> SupportedCompressionAlgorithms = [ AlgorithmNames.None ];
    internal readonly static List<Name> DisableCompressionAlgorithms = [ AlgorithmNames.None ];
    internal readonly static List<Name> DefaultKeyExchangeAlgorithms = SupportedKeyExchangeAlgorithms;
    internal readonly static List<Name> DefaultServerHostKeyAlgorithms = SupportedServerHostKeyAlgorithms;
    internal readonly static List<Name> DefaultEncryptionAlgorithms = SupportedEncryptionAlgorithms;
    internal readonly static List<Name> DefaultMacAlgorithms = SupportedMacAlgorithms;
    internal readonly static List<Name> DefaultCompressionAlgorithms = SupportedCompressionAlgorithms;
    internal readonly static List<Name> EnableCompressionAlgorithms = DisableCompressionAlgorithms; // no compression algorithms implemented.

    private static IReadOnlyList<Credential> CreateDefaultCredentials()
    {
        List<Credential> credentials = new();
        foreach (var identityFile in DefaultIdentityFiles)
        {
            credentials.Add(new PrivateKeyCredential(identityFile));
        }
        credentials.Add(new SshAgentCredentials());
        credentials.Add(new KerberosCredential());
        credentials.Add(new NoCredential());
        return credentials.AsReadOnly();
    }

    private static List<Name> CreatePreferredEncryptionAlgorithms()
    {
        // The preferred encryption algorithms must only include algorithms that are considered secure.
        // We make an attempt to order them fastest to slowest.

        // Prefer AesGcm over ChaCha20Poly when the platform has AES instructions.
        bool addAesGcm = AesGcm.IsSupported;
        bool hasAesInstructions = System.Runtime.Intrinsics.X86.Aes.X64.IsSupported ||
                                  System.Runtime.Intrinsics.X86.Aes.IsSupported ||
                                  System.Runtime.Intrinsics.Arm.Aes.IsSupported ||
                                  System.Runtime.Intrinsics.Arm.Aes.Arm64.IsSupported;

        List<Name> algorithms = new List<Name>();

        if (addAesGcm && hasAesInstructions)
        {
            AddAesGcmAlgorithms(algorithms);
            addAesGcm = false;
        }

        algorithms.Add(AlgorithmNames.ChaCha20Poly1305);

        if (addAesGcm)
        {
            Debug.Assert(!hasAesInstructions);
            AddAesGcmAlgorithms(algorithms);
        }

        return algorithms;

        static void AddAesGcmAlgorithms(List<Name> algorithms)
        {
            algorithms.Add(AlgorithmNames.Aes256Gcm);
            algorithms.Add(AlgorithmNames.Aes128Gcm);
        }
    }

    private static IReadOnlyList<string> CreateDefaultGlobalKnownHostsFilePaths()
    {
        string path;
        if (Platform.IsWindows)
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
